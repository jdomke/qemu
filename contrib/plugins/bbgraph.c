/*
 * Extract basic block graphs for Machine Code analysis tools.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <glib.h>
#include <assert.h>

#include "qemu-plugin.h"
#include "json.h"

typedef struct Bblock_t {
    uint64_t vaddr;
    struct qemu_plugin_scoreboard *count;
    unsigned int index;
} Bblock_t;

typedef struct Vcpu_t {
    FILE *file;
} Vcpu_t;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static GHashTable *bblock_htable;
static GRWLock bblock_htable_lock;

static char *out_prefix;
static struct qemu_plugin_scoreboard *vcpus;

static void file_names_mapping_to_json(json_object *);
static void symbol_data_mapping_to_json(uint64_t, json_object *);
static void source_data_mapping_to_json(uint64_t, json_object *);
static void basic_blocks_mapping_to_json(uint64_t, json_object *);
static void routines_mapping_to_json(uint64_t, json_object *);
static void image_data_mapping_to_json(uint64_t, json_object *);
static void images_mapping_to_json(pid_t, json_object *);
static void edges_mapping_to_json(json_object *);
static void process_data_mapping_to_json(pid_t, json_object *);
static void processes_mapping_to_json(json_object *);

static void plugin_exit(qemu_plugin_id_t id, void *p);
static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index);
static void vcpu_exit(unsigned int vcpu_index, void *udata);
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);
static void free_scoreboard_bb_data(void *data);
static qemu_plugin_u64 bb_count_u64(Bblock_t *bb);

static void file_names_mapping_to_json(json_object *file_names)
{
    assert(json_object_is_type(file_names, json_type_array));

    /* Example:
     * "FILE_NAMES" :
     *   [ [ "FILE_NAME_ID", "FILE_NAME" ],                                     // use inode as ID
     *     [ 2, “\/usr\/joe\/src\/misc\/hello-world" ],
     *     [ 5, "\/lib64\/libgcc_s.so" ],
     *     [ 4, “\/usr\/joe\/src\/misc\/hello-world.c" ],
     *   ]
     */
    json_object *fn_obj = json_object_new_array();
    json_object_array_add(fn_obj, json_object_new_string("FILE_NAME_ID"));
    json_object_array_add(fn_obj, json_object_new_string("FILE_NAME"));
    json_object_array_add(file_names, fn_obj);

    pid_t pid = getpid();
    char pidmap_filename[128];
    snprintf(pidmap_filename, sizeof(pidmap_filename), "/proc/%d/maps", pid);
    FILE *pidmap_file = fopen(pidmap_filename, "r");
    assert(pidmap_file);

    char line[128+(128+256)];
    uint64_t start, end, priv_inode = 0; // first appearance in maps seems file
    char perms[5], offset[9], dev[6], inode[11];
    char filepath[128+256];

    while (fgets(line, sizeof(line), pidmap_file)) {
        // parse the line for start, end, permissions, offset, etc.
        if (sscanf(line, "%lx-%lx %4s %8s %5s %10s %255s",
                   &start, &end, perms, offset, dev, inode, filepath) >= 6) {
	    fprintf(stderr, "%s\n", line);
            if (perms[0] == 'r' && perms[1] != 'w'
                && 0 < atol(inode) && priv_inode != atol(inode)) {
                //fprintf(stderr,
                //        "start: 0x%lx, end: 0x%lx, permissions: %s, path: %s\n",
                //        start, end, perms, filepath);

                // Create a new JSON object for this mapping
                fn_obj = json_object_new_array();
                // Add key-value pairs to the JSON object
                json_object_array_add(fn_obj, json_object_new_uint64((priv_inode = atol(inode))));
                json_object_array_add(fn_obj, json_object_new_string(filepath));
                json_object_array_add(file_names, fn_obj);
            }
        }
    }

    fclose(pidmap_file);
}

static void symbol_data_mapping_to_json(uint64_t inode, json_object *symbol_data)
{
    assert(json_object_is_type(symbol_data, json_type_array));

    /* Example:
     * [ [ "NAME", "ADDR_OFFSET", "SIZE " ],
     *   [ "free", "0x127f0", 60 ],
     *   [ "malloc", "0x12940", 13 ],
     *   [ "calloc", "0x12a00", 9 ]
     * ]
     */
    json_object *s_obj = json_object_new_array();
    json_object_array_add(s_obj, json_object_new_string("NAME"));
    json_object_array_add(s_obj, json_object_new_string("ADDR_OFFSET"));
    json_object_array_add(s_obj, json_object_new_string("SIZE"));
    json_object_array_add(symbol_data, s_obj);
}

static void source_data_mapping_to_json(uint64_t inode, json_object *source_data)
{
    assert(json_object_is_type(source_data, json_type_array));

    /* Example:
     * [ [ "FILE_NAME_ID", "LINE_NUM", "ADDR_OFFSET", "SIZE", "NUM_INSTRS" ],
     *   [ 8, 25, "0x7a8", 4, 1 ],
     *   [ 8, 26, "0x7ac", 5, 1 ],
     *   [ 9, 9, "0x7bb", 4, 1 ],
     * ]
     */
    json_object *s_obj = json_object_new_array();
    json_object_array_add(s_obj, json_object_new_string("FILE_NAME_ID"));
    json_object_array_add(s_obj, json_object_new_string("LINE_NUM"));
    json_object_array_add(s_obj, json_object_new_string("ADDR_OFFSET"));
    json_object_array_add(s_obj, json_object_new_string("SIZE"));
    json_object_array_add(s_obj, json_object_new_string("NUM_INSTRS"));
    json_object_array_add(source_data, s_obj);
}

static void basic_blocks_mapping_to_json(uint64_t inode, json_object *basic_blocks)
{
    assert(json_object_is_type(basic_blocks, json_type_array));

    /* Example:
     * [ [ "NODE_ID", "ADDR_OFFSET", "SIZE", "NUM_INSTRS", "LAST_INSTR_OFFSET", "COUNT" ],
     *   [ 4, "0x7a8", 9, 2, 4, 1 ],
     *   [ 5, "0x7b1", 5, 1, 0, 9 ],
     *   [ 6, "0x7b6", 5, 1, 0, 8 ],
     * ]
     */
    json_object *b_obj = json_object_new_array();
    json_object_array_add(b_obj, json_object_new_string("NODE_ID"));
    json_object_array_add(b_obj, json_object_new_string("ADDR_OFFSET"));
    json_object_array_add(b_obj, json_object_new_string("SIZE"));
    json_object_array_add(b_obj, json_object_new_string("NUM_INSTRS"));
    json_object_array_add(b_obj, json_object_new_string("LAST_INSTR_OFFSET"));
    json_object_array_add(b_obj, json_object_new_string("COUNT"));
    json_object_array_add(basic_blocks, b_obj);
}

static void routines_mapping_to_json(uint64_t inode, json_object *routines)
{
    assert(json_object_is_type(routines, json_type_array));

    /* Example:
     * [ [ "ENTRY_NODE_ID", "EXIT_NODE_IDS", "NODES", "LOOPS" ],
     *   [ 4, [ 4, 5, 6, 7 ],
     *     [ [ "NODE_ID", "IDOM_NODE_ID" ],
     *       [ 4, 4 ],
     *       [ 5, 4 ],
     *       [ 6, 5 ],
     *       [ 7, 6 ] ] ],
     *       [ 63, [ 65, 67 ],
     *     [ [ "NODE_ID", "IDOM_NODE_ID" ],
     *       [ 66, 65 ],
     *       [ 67, 63 ],
     *       [ 63, 63 ],
     *       [ 64, 63 ],
     *       [ 65, 64 ] ], [...]
     * ]
     */
    json_object *r_obj = json_object_new_array();
    json_object_array_add(r_obj, json_object_new_string("ENTRY_NODE_ID"));
    json_object_array_add(r_obj, json_object_new_string("EXIT_NODE_IDS"));
    json_object_array_add(r_obj, json_object_new_string("NODES"));
    json_object_array_add(r_obj, json_object_new_string("LOOPS"));
    json_object_array_add(routines, r_obj);
}

static void image_data_mapping_to_json(uint64_t inode, json_object *image_data)
{
    assert(json_object_is_type(image_data, json_type_object));

    /* Example:
     * { "FILE_NAME_ID" : 4,
     *   "SYMBOLS" : [...],
     *   "SOURCE_DATA" : [...],
     *   "BASIC_BLOCKS" : [...],
     *   "ROUTINES" : [...]
     * }
     */
    json_object_object_add(image_data,
                           "FILE_NAME_ID", json_object_new_uint64(inode));

    json_object *symbol_data = json_object_new_array();
    symbol_data_mapping_to_json(inode, symbol_data);
    json_object_object_add(image_data, "SYMBOLS", symbol_data);

    json_object *source_data = json_object_new_array();
    source_data_mapping_to_json(inode, source_data);
    json_object_object_add(image_data, "SOURCE_DATA", source_data);

    json_object *basic_blocks = json_object_new_array();
    basic_blocks_mapping_to_json(inode, basic_blocks);
    json_object_object_add(image_data, "BASIC_BLOCKS", basic_blocks);

    json_object *routines = json_object_new_array();
    routines_mapping_to_json(inode, routines);
    json_object_object_add(image_data, "ROUTINES", routines);
}

static void images_mapping_to_json(pid_t pid, json_object *images)
{
    assert(json_object_is_type(images, json_type_array));

    /* Example:
     * [ [ "IMAGE_ID", "LOAD_ADDR", "SIZE", "IMAGE_DATA" ],                     // use inode as ID
     *   [ 1, "0x400000", 2102216, {...} ],
     *   [ 2, "0x2aaaaaaab000", 1166728, {...} ]
     * ]
     */
    char pidmap_filename[128], load_addr[32];
    snprintf(pidmap_filename, sizeof(pidmap_filename), "/proc/%d/maps", pid);
    FILE *pidmap_file = fopen(pidmap_filename, "r");
    assert(pidmap_file);

    json_object *im_obj = json_object_new_array();
    json_object_array_add(im_obj, json_object_new_string("IMAGE_ID"));
    json_object_array_add(im_obj, json_object_new_string("LOAD_ADDR"));
    json_object_array_add(im_obj, json_object_new_string("SIZE"));
    json_object_array_add(im_obj, json_object_new_string("IMAGE_DATA"));
    json_object_array_add(images, im_obj);

    char line[128+(128+256)];
    uint64_t start, end, priv_inode = 0;
    char perms[5], offset[9], dev[6], inode[11];
    char filename[128+256];
    json_object *im_data_obj = NULL;

    while (fgets(line, sizeof(line), pidmap_file)) {
        // parse the line for start, end, permissions, offset, etc.
        if (sscanf(line, "%lx-%lx %4s %8s %5s %10s %255s",
                   &start, &end, perms, offset, dev, inode, filename) >= 6) {
            if (perms[0] == 'r' && perms[1] != 'w'
                && 0 < atol(inode) && priv_inode != atol(inode)) {
                //fprintf(stderr,
                //        "start: 0x%lx, end: 0x%lx, permissions: %s, path: %s\n",
                //        start, end, perms, filename);

                // Create a new JSON object for this mapping
                im_obj = json_object_new_array();
                // Add key-value pairs to the JSON object
                json_object_array_add(im_obj, json_object_new_uint64((priv_inode = atol(inode))));
                snprintf(load_addr, sizeof(load_addr), "0x%"PRIx64, start);
                json_object_array_add(im_obj, json_object_new_string(load_addr));
                json_object_array_add(im_obj, json_object_new_uint64(end-start));

                im_data_obj = json_object_new_object();
                image_data_mapping_to_json(atol(inode), im_data_obj);
                json_object_array_add(im_obj, im_data_obj);

                json_object_array_add(images, im_obj);
            }
        }
    }

    fclose(pidmap_file);
}

static void edges_mapping_to_json(json_object *edges)
{
    assert(json_object_is_type(edges, json_type_array));

    /* Example (this process had 6 threads):
     * [ [ "EDGE_ID", "SOURCE_NODE_ID", "TARGET_NODE_ID", "EDGE_TYPE_ID", "COUNT_PER_THREAD" ],
     *   [ 4810, 1683, 3002, 16, [ 0, 0, 1, 1, 1, 0 ] ],
     *   [ 3460, 1597, 1598, 18, [ 1, 0, 0, 0, 0, 0 ] ],
     *   [ 953, 1597, 1599, 13, [ 7, 0, 0, 0, 0, 0 ] ]
     * ]
     */
    json_object *e_obj = json_object_new_array();
    json_object_array_add(e_obj, json_object_new_string("EDGE_ID"));
    json_object_array_add(e_obj, json_object_new_string("SOURCE_NODE_ID"));
    json_object_array_add(e_obj, json_object_new_string("TARGET_NODE_ID"));
    json_object_array_add(e_obj, json_object_new_string("EDGE_TYPE_ID"));
    json_object_array_add(e_obj, json_object_new_string("COUNT_PER_THREAD"));
    json_object_array_add(edges, e_obj);

    //FIXME
    e_obj = json_object_new_array();
    json_object_array_add(e_obj, json_object_new_uint64(0));
    json_object_array_add(e_obj, json_object_new_uint64(0));
    json_object_array_add(e_obj, json_object_new_uint64(0));
    json_object_array_add(e_obj, json_object_new_uint64(0));
    json_object_array_add(e_obj, json_object_new_array_ext(qemu_plugin_num_vcpus()));
    json_object_array_add(edges, e_obj);
}

static void process_data_mapping_to_json(pid_t pid, json_object *process_data)
{
    assert(json_object_is_type(process_data, json_type_object));

    /* Example:
     * { "INSTR_COUNT" : 2134576,
     *   "INSTR_COUNT_PER_THREAD" : [ 1997750, 51676, 19794, 18381, 19598 ],
     *   "IMAGES" : [...],
     *   "EDGES" : [...]
     * }
     */
    json_object_object_add(process_data,
                           "INSTR_COUNT", json_object_new_uint64(0));
    json_object_object_add(process_data,
                           "INSTR_COUNT_PER_THREAD", json_object_new_array_ext(qemu_plugin_num_vcpus()));

    json_object *images_obj = json_object_new_array();
    images_mapping_to_json(pid, images_obj);
    json_object *edges_obj = json_object_new_array();
    edges_mapping_to_json(edges_obj);
    json_object_object_add(process_data, "IMAGES", images_obj);
    json_object_object_add(process_data, "EDGES", edges_obj);
}

static void processes_mapping_to_json(json_object *processes)
{
    assert(json_object_is_type(processes, json_type_array));

    /* Example:
     * "PROCESSES" :
     *   [ [ "PROCESS_ID", "PROCESS_DATA" ],
     *     [ 22814, {...} ],
     *     [ 958, {...} ]
     *   ]
     */
    json_object *p_obj = json_object_new_array();
    json_object_array_add(p_obj, json_object_new_string("PROCESS_ID"));
    json_object_array_add(p_obj, json_object_new_string("PROCESS_DATA"));
    json_object_array_add(processes, p_obj);

    p_obj = json_object_new_array();
    pid_t pid = getpid();
    json_object *pd_obj = json_object_new_object();
    process_data_mapping_to_json(pid, pd_obj);
    json_object_array_add(p_obj, json_object_new_uint64(pid));
    json_object_array_add(p_obj, pd_obj);

    json_object_array_add(processes, p_obj);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_autofree gchar *json_out_file = g_strdup_printf("%s.json", out_prefix);
    FILE *json_out_fd = fopen(json_out_file, "w");
    if (!json_out_fd)
        return;

    // Create a new JSON object (an empty object {})
    json_object *bbgraph_json = json_object_new_object();
    /* Derived from SDE's format: https://www.intel.com/content/dam/develop/external/us/en/documents/dcfg-format-548994.pdf
     * top-level object:
        { "MAJOR_VERSION" : 0,
          "MINOR_VERSION" : 6,
          "FILE_NAMES" : [...],
          "EDGE_TYPES" : [...],
          "SPECIAL_NODES" : [...],
          "PROCESSES" : [...],
        }
     */
    json_object_object_add(bbgraph_json,
                           "MAJOR_VERSION", json_object_new_uint64(0));
    json_object_object_add(bbgraph_json,
                           "MINOR_VERSION", json_object_new_uint64(1));

    json_object *FILE_NAMES = json_object_new_array();
    json_object *EDGE_TYPES = json_object_new_array();                          // ignore for now
    json_object *SPECIAL_NODES = json_object_new_array();                       // ignore for now
    json_object *PROCESSES = json_object_new_array();
    file_names_mapping_to_json(FILE_NAMES);
    processes_mapping_to_json(PROCESSES);
    json_object_object_add(bbgraph_json, "FILE_NAMES", FILE_NAMES);
    json_object_object_add(bbgraph_json, "EDGE_TYPES", EDGE_TYPES);
    json_object_object_add(bbgraph_json, "SPECIAL_NODES", SPECIAL_NODES);
    json_object_object_add(bbgraph_json, "PROCESSES", PROCESSES);

    // Convert the JSON object to a string
    const char *json_str = json_object_to_json_string_ext(bbgraph_json,
                                                          (JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
    // Write the JSON string to the file
    fprintf(json_out_fd, "%s\n", json_str);

    for (int i = 0; i < qemu_plugin_num_vcpus(); i++)
        vcpu_exit(i, NULL);

    g_hash_table_unref(bblock_htable);
    g_free(out_prefix);
    qemu_plugin_scoreboard_free(vcpus);

    // Free the JSON object memory
    json_object_put(bbgraph_json);

    fclose(json_out_fd);
}

static void free_scoreboard_bb_data(void *data)
{
    qemu_plugin_scoreboard_free(((Bblock_t *)data)->count);
    g_free(data);
}

static qemu_plugin_u64 bb_count_u64(Bblock_t *bb)
{
    return qemu_plugin_scoreboard_u64(bb->count);
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
//    Vcpu_t *vcpu = qemu_plugin_scoreboard_find(vcpus, vcpu_index);
}

static void vcpu_exit(unsigned int vcpu_index, void *udata)
{
    return;

    //Vcpu_t *vcpu = qemu_plugin_scoreboard_find(vcpus, vcpu_index);
    GHashTableIter iter;
    void *value;

    g_rw_lock_reader_lock(&bblock_htable_lock);
    g_hash_table_iter_init(&iter, bblock_htable);

    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        Bblock_t *bb = value;
        uint64_t bb_count = qemu_plugin_u64_get(bb_count_u64(bb), vcpu_index);

        if (!bb_count) {
            continue;
        }

        fprintf(stderr, ":%u:%" PRIu64 " ", bb->index, bb_count);
        qemu_plugin_u64_set(bb_count_u64(bb), vcpu_index, 0);
    }

    g_rw_lock_reader_unlock(&bblock_htable_lock);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t n_insns = qemu_plugin_tb_n_insns(tb);
    uint64_t vaddr = qemu_plugin_tb_vaddr(tb);
    Bblock_t *bb;

    g_rw_lock_writer_lock(&bblock_htable_lock);


    bb = g_hash_table_lookup(bblock_htable, &vaddr);
    if (!bb) {
        bb = g_new(Bblock_t, 1);
        assert(bb);
        bb->vaddr = vaddr;
        bb->count = qemu_plugin_scoreboard_new(sizeof(uint64_t));
        bb->index = g_hash_table_size(bblock_htable);
        g_hash_table_replace(bblock_htable, &bb->vaddr, bb);
    }
    g_rw_lock_writer_unlock(&bblock_htable_lock);

    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64, bb_count_u64(bb), n_insns);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    if (info->system_emulation) {
        fputs("ERR: currently not supporting full system emulation\n", stderr);
        return -1;
    }

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "outfile") == 0) {
            out_prefix = tokens[1];
            tokens[1] = NULL;
        } else {
            fprintf(stderr, "ERR: option parsing failed: %s\n", opt);
            return -1;
        }
    }

    if (!out_prefix) {
        fputs("ERR: outfile unspecified\n", stderr);
        return -1;
    }

    bblock_htable = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL,
                                          free_scoreboard_bb_data);
    vcpus = qemu_plugin_scoreboard_new(sizeof(Vcpu_t));
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

    return 0;
}
