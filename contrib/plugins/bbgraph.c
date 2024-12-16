/*
 * Extract basic block graphs for Machine Code analysis tools.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <glib.h>

#include "qemu-plugin.h"
#include "json.h"

typedef struct EdgeData_t {
    uint64_t dst_bb_id;                    // TARGET_NODE_ID for an edge/jump
    struct qemu_plugin_scoreboard *count;  // COUNT_PER_THREAD for this edge
} EdgeData_t;

typedef struct Bblock_t {
    GRWLock lock;
    uint64_t bb_id;                        // key for the hash table
    uint64_t table_idx;                    // NODE_ID
    uint64_t vaddr;                        // ADDR_OFFSET (use absolute)
    //uint32_t size;                         // SIZE of the block in bytes
    uint32_t n_ins;                        // NUM_INSTRS n this block
    //uint64_t vaddr_last_instr;             // LAST_INSTR_OFFSET
    struct qemu_plugin_scoreboard *count;  // COUNT of times this was executed
    GArray *edges;
} Bblock_t;

/* We use this to track the current execution state */
typedef struct Vcpu_t {
    uint64_t n_insn;      /* number instructions executed */
    uint64_t prev_bb_id;  /* block ID of the previous block */
    uint64_t pc_after_bb; /* next pc right after the end of a basicblock */
} Vcpu_t;

/* descriptors for accessing the above scoreboard */
static qemu_plugin_u64 n_insn;
static qemu_plugin_u64 prev_bb_id;
static qemu_plugin_u64 pc_after_bb;
struct qemu_plugin_scoreboard *processor_state;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static GHashTable *bblock_htable;
static GRWLock bblock_htable_lock;

static char *out_prefix;

static void file_names_mapping_to_json(json_object *);
static void edge_types_mapping_to_json(json_object *);
static void special_nodes_mapping_to_json(json_object *);
static void symbol_data_mapping_to_json(uint64_t, json_object *);
static void source_data_mapping_to_json(uint64_t, json_object *);
static void basic_blocks_mapping_to_json(uint64_t, uint64_t, uint64_t, json_object *);
static void routines_mapping_to_json(uint64_t, json_object *);
static void image_data_mapping_to_json(uint64_t, uint64_t, uint64_t, json_object *);
static void images_mapping_to_json(pid_t, json_object *);
static void edges_mapping_to_json(json_object *);
static void process_data_mapping_to_json(pid_t, json_object *);
static void processes_mapping_to_json(json_object *);
static void bbgraph_to_json(FILE *);

static void plugin_init(void);
static void plugin_exit(qemu_plugin_id_t, void *);
static void vcpu_tb_branched_exec(unsigned int, void *);
static void vcpu_tb_trans(qemu_plugin_id_t, struct qemu_plugin_tb *);
static void free_scoreboard_bb_data(void *);

static void file_names_mapping_to_json(json_object *file_names)
{
    g_assert(json_object_is_type(file_names, json_type_array));

    /* Example:
     * "FILE_NAMES" :
     *  [ [ "FILE_NAME_ID", "FILE_NAME" ],                                     // use inode as ID
     *    [ 2, “\/usr\/joe\/src\/misc\/hello-world" ],
     *    [ 5, "\/lib64\/libgcc_s.so" ],
     *    [ 4, “\/usr\/joe\/src\/misc\/hello-world.c" ],
     *  ]
     */
    json_object *fn_obj = json_object_new_array_ext(2);
    json_object_array_add(fn_obj, json_object_new_string("FILE_NAME_ID"));
    json_object_array_add(fn_obj, json_object_new_string("FILE_NAME"));
    json_object_array_add(file_names, fn_obj);

    pid_t pid = getpid();
    char pidmap_filename[128];
    snprintf(pidmap_filename, sizeof(pidmap_filename), "/proc/%d/maps", pid);
    FILE *pidmap_file = fopen(pidmap_filename, "r");
    g_assert(pidmap_file);

    char line[128+(128+256)];
    uint64_t start, end, prev_inode = 0; // first appearance in maps seems file
    char perms[5], offset[9], dev[6], inode[11];
    char filepath[128+256];

    while (fgets(line, sizeof(line), pidmap_file)) {
        // parse the line for start, end, permissions, offset, etc.
        if (sscanf(line, "%lx-%lx %4s %8s %5s %10s %255s",
                   &start, &end, perms, offset, dev, inode, filepath) >= 6) {
            //fprintf(stderr, "%s\n", line);
            if (perms[0] == 'r' && perms[1] != 'w'
                && 0 < atol(inode) && prev_inode != atol(inode)) {
                //fprintf(stderr,
                //        "start: 0x%lx, end: 0x%lx, permissions: %s, path: %s\n",
                //        start, end, perms, filepath);

                // Create a new JSON object for this mapping
                fn_obj = json_object_new_array_ext(2);
                // Add key-value pairs to the JSON object
                json_object_array_add(fn_obj, json_object_new_uint64((prev_inode = atol(inode))));
                json_object_array_add(fn_obj, json_object_new_string(filepath));
                json_object_array_add(file_names, fn_obj);
            }
        }
    }

    fclose(pidmap_file);
}

static void edge_types_mapping_to_json(json_object *edge_types)
{
    g_assert(json_object_is_type(edge_types, json_type_array));

    /* Example:
     * "EDGE_TYPES" :
     *  [ [ "EDGE_TYPE_ID", "EDGE_TYPE" ],
     *    [ 1, "ENTRY" ],
     *    ...
     *    [ 27, "UNKNOWN" ]
     *  ]
     */
    json_object *e_obj = json_object_new_array_ext(2);
    json_object_array_add(e_obj, json_object_new_string("EDGE_TYPE_ID"));
    json_object_array_add(e_obj, json_object_new_string("EDGE_TYPE"));
    json_object_array_add(edge_types, e_obj);
    e_obj = json_object_new_array_ext(2);
    json_object_array_add(e_obj, json_object_new_uint64(27));
    json_object_array_add(e_obj, json_object_new_string("UNKNOWN"));
    json_object_array_add(edge_types, e_obj);
}

static void special_nodes_mapping_to_json(json_object *special_nodes)
{
    g_assert(json_object_is_type(special_nodes, json_type_array));

    /* Example:
     * "SPECIAL_NODES" :
     *  [ [ "NODE_ID", "NODE_NAME" ],
     *    [ 1, "START" ],
     *    [ 2, "END" ],
     *    [ 3, "UNKNOWN" ]
     *  ]
     */
    json_object *s_obj = json_object_new_array_ext(2);
    json_object_array_add(s_obj, json_object_new_string("NODE_ID"));
    json_object_array_add(s_obj, json_object_new_string("NODE_NAME"));
    json_object_array_add(special_nodes, s_obj);
    s_obj = json_object_new_array_ext(2);
    json_object_array_add(s_obj, json_object_new_uint64(3));
    json_object_array_add(s_obj, json_object_new_string("UNKNOWN"));
    json_object_array_add(special_nodes, s_obj);
}

static void symbol_data_mapping_to_json(uint64_t inode,
                                        json_object *symbol_data)
{
    g_assert(json_object_is_type(symbol_data, json_type_array));

    /* Example:
     *  [ [ "NAME", "ADDR_OFFSET", "SIZE " ],
     *    [ "free", "0x127f0", 60 ],
     *    [ "malloc", "0x12940", 13 ],
     *    [ "calloc", "0x12a00", 9 ]
     *  ]
     */
    json_object *s_obj = json_object_new_array_ext(3);
    json_object_array_add(s_obj, json_object_new_string("NAME"));
    json_object_array_add(s_obj, json_object_new_string("ADDR_OFFSET"));
    json_object_array_add(s_obj, json_object_new_string("SIZE"));
    json_object_array_add(symbol_data, s_obj);
}

static void source_data_mapping_to_json(uint64_t inode,
                                        json_object *source_data)
{
    g_assert(json_object_is_type(source_data, json_type_array));

    /* Example:
     *  [ [ "FILE_NAME_ID", "LINE_NUM", "ADDR_OFFSET", "SIZE", "NUM_INSTRS" ],
     *    [ 8, 25, "0x7a8", 4, 1 ],
     *    [ 8, 26, "0x7ac", 5, 1 ],
     *    [ 9, 9, "0x7bb", 4, 1 ],
     *  ]
     */
    json_object *s_obj = json_object_new_array_ext(5);
    json_object_array_add(s_obj, json_object_new_string("FILE_NAME_ID"));
    json_object_array_add(s_obj, json_object_new_string("LINE_NUM"));
    json_object_array_add(s_obj, json_object_new_string("ADDR_OFFSET"));
    json_object_array_add(s_obj, json_object_new_string("SIZE"));
    json_object_array_add(s_obj, json_object_new_string("NUM_INSTRS"));
    json_object_array_add(source_data, s_obj);
}

static void basic_blocks_mapping_to_json(uint64_t inode,
                                         uint64_t vaddr_start,
                                         uint64_t vaddr_end,
                                         json_object *basic_blocks)
{
    g_assert(json_object_is_type(basic_blocks, json_type_array));

    /* Example:
     *  [ [ "NODE_ID", "ADDR_OFFSET", "SIZE", "NUM_INSTRS", "LAST_INSTR_OFFSET", "COUNT" ],
     *    [ 4, "0x7a8", 9, 2, 4, 1 ],
     *    [ 5, "0x7b1", 5, 1, 0, 9 ],
     *    [ 6, "0x7b6", 5, 1, 0, 8 ],
     *  ]
     */
    json_object *b_obj = json_object_new_array_ext(6);
    json_object_array_add(b_obj, json_object_new_string("NODE_ID"));
    json_object_array_add(b_obj, json_object_new_string("ADDR_OFFSET"));
    json_object_array_add(b_obj, json_object_new_string("SIZE"));
    json_object_array_add(b_obj, json_object_new_string("NUM_INSTRS"));
    json_object_array_add(b_obj, json_object_new_string("LAST_INSTR_OFFSET"));
    json_object_array_add(b_obj, json_object_new_string("COUNT"));
    json_object_array_add(basic_blocks, b_obj);

    g_rw_lock_reader_lock(&bblock_htable_lock);

    GHashTableIter iter;
    Bblock_t *bb = NULL;
    char bb_addr[32];
    uint64_t total_exec = 0;

    g_hash_table_iter_init(&iter, bblock_htable);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer*)&bb)) {
        if (bb->vaddr < vaddr_start || bb->vaddr > vaddr_end)
            continue;

        b_obj = json_object_new_array_ext(6);
        json_object_array_add(b_obj, json_object_new_uint64(bb->bb_id));
        snprintf(bb_addr, sizeof(bb_addr), "0x%"PRIx64, bb->vaddr - vaddr_start);
        json_object_array_add(b_obj, json_object_new_string(bb_addr));
        json_object_array_add(b_obj, json_object_new_uint64(0)); //(bb->size));
        json_object_array_add(b_obj, json_object_new_uint64(bb->n_ins));
        json_object_array_add(b_obj, json_object_new_uint64(0)); //(bb->vaddr_last_instr));
        total_exec = 0;
        for (int vcpu_idx = 0; vcpu_idx < qemu_plugin_num_vcpus(); vcpu_idx++)
            total_exec += qemu_plugin_u64_get(qemu_plugin_scoreboard_u64(bb->count), vcpu_idx);
        json_object_array_add(b_obj, json_object_new_uint64(total_exec));
        json_object_array_add(basic_blocks, b_obj);
    }

    g_rw_lock_reader_unlock(&bblock_htable_lock);
}

static void routines_mapping_to_json(uint64_t inode, json_object *routines)
{
    g_assert(json_object_is_type(routines, json_type_array));

    /* Example:
     *  [ [ "ENTRY_NODE_ID", "EXIT_NODE_IDS", "NODES", "LOOPS" ],
     *    [ 4, [ 4, 5, 6, 7 ],
     *      [ [ "NODE_ID", "IDOM_NODE_ID" ],
     *        [ 4, 4 ],
     *        [ 5, 4 ],
     *        [ 6, 5 ],
     *        [ 7, 6 ] ] ],
     *        [ 63, [ 65, 67 ],
     *      [ [ "NODE_ID", "IDOM_NODE_ID" ],
     *        [ 66, 65 ],
     *        [ 67, 63 ],
     *        [ 63, 63 ],
     *        [ 64, 63 ],
     *        [ 65, 64 ] ], [...]
     *  ]
     */
    json_object *r_obj = json_object_new_array_ext(4);
    json_object_array_add(r_obj, json_object_new_string("ENTRY_NODE_ID"));
    json_object_array_add(r_obj, json_object_new_string("EXIT_NODE_IDS"));
    json_object_array_add(r_obj, json_object_new_string("NODES"));
    json_object_array_add(r_obj, json_object_new_string("LOOPS"));
    json_object_array_add(routines, r_obj);
}

static void image_data_mapping_to_json(uint64_t inode,
                                       uint64_t vaddr_start,
                                       uint64_t vaddr_end,
                                       json_object *image_data)
{
    g_assert(json_object_is_type(image_data, json_type_object));

    /* Example:
     *  { "FILE_NAME_ID" : 4,
     *    "SYMBOLS" : [...],
     *    "SOURCE_DATA" : [...],
     *    "BASIC_BLOCKS" : [...],
     *    "ROUTINES" : [...]
     *  }
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
    basic_blocks_mapping_to_json(inode, vaddr_start, vaddr_end, basic_blocks);
    json_object_object_add(image_data, "BASIC_BLOCKS", basic_blocks);

    json_object *routines = json_object_new_array();
    routines_mapping_to_json(inode, routines);
    json_object_object_add(image_data, "ROUTINES", routines);
}

static void images_mapping_to_json(pid_t pid, json_object *images)
{
    g_assert(json_object_is_type(images, json_type_array));

    /* Example:
     *  [ [ "IMAGE_ID", "LOAD_ADDR", "SIZE", "IMAGE_DATA" ],                     // use inode as ID
     *    [ 1, "0x400000", 2102216, {...} ],
     *    [ 2, "0x2aaaaaaab000", 1166728, {...} ]
     *  ]
     */
    char pidmap_filename[128], load_addr[32];
    snprintf(pidmap_filename, sizeof(pidmap_filename), "/proc/%d/maps", pid);
    FILE *pidmap_file = fopen(pidmap_filename, "r");
    g_assert(pidmap_file);

    json_object *im_obj = json_object_new_array_ext(4);
    json_object_array_add(im_obj, json_object_new_string("IMAGE_ID"));
    json_object_array_add(im_obj, json_object_new_string("LOAD_ADDR"));
    json_object_array_add(im_obj, json_object_new_string("SIZE"));
    json_object_array_add(im_obj, json_object_new_string("IMAGE_DATA"));
    json_object_array_add(images, im_obj);

    char line[128+(128+256)];
    uint64_t start, end, prev_inode = 0;
    char perms[5], offset[9], dev[6], inode[11];
    char filename[128+256];
    json_object *im_data_obj = NULL;

    while (fgets(line, sizeof(line), pidmap_file)) {
        // parse the line for start, end, permissions, offset, etc.
        if (sscanf(line, "%lx-%lx %4s %8s %5s %10s %255s",
                   &start, &end, perms, offset, dev, inode, filename) >= 6) {
            if (perms[0] == 'r' && perms[1] != 'w'
                && 0 < atol(inode) && prev_inode != atol(inode)) {
                //fprintf(stderr,
                //        "start: 0x%lx, end: 0x%lx, permissions: %s, path: %s\n",
                //        start, end, perms, filename);

                // Create a new JSON object for this mapping
                im_obj = json_object_new_array_ext(4);
                // Add key-value pairs to the JSON object
                json_object_array_add(im_obj, json_object_new_uint64((prev_inode = atol(inode))));
                snprintf(load_addr, sizeof(load_addr), "0x%"PRIx64, start);
                json_object_array_add(im_obj, json_object_new_string(load_addr));
                json_object_array_add(im_obj, json_object_new_uint64(end-start));

                im_data_obj = json_object_new_object();
                image_data_mapping_to_json(atol(inode), start, end, im_data_obj);
                json_object_array_add(im_obj, im_data_obj);

                json_object_array_add(images, im_obj);
            }
        }
    }

    fclose(pidmap_file);
}

static void edges_mapping_to_json(json_object *edges)
{
    g_assert(json_object_is_type(edges, json_type_array));

    /* Example (this process had 6 threads):
     *  [ [ "EDGE_ID", "SOURCE_NODE_ID", "TARGET_NODE_ID", "EDGE_TYPE_ID", "COUNT_PER_THREAD" ],
     *    [ 4810, 1683, 3002, 16, [ 0, 0, 1, 1, 1, 0 ] ],
     *    [ 3460, 1597, 1598, 18, [ 1, 0, 0, 0, 0, 0 ] ],
     *    [ 953, 1597, 1599, 13, [ 7, 0, 0, 0, 0, 0 ] ]
     *  ]
     */
    json_object *e_obj = json_object_new_array_ext(5);
    json_object_array_add(e_obj, json_object_new_string("EDGE_ID"));
    json_object_array_add(e_obj, json_object_new_string("SOURCE_NODE_ID"));
    json_object_array_add(e_obj, json_object_new_string("TARGET_NODE_ID"));
    json_object_array_add(e_obj, json_object_new_string("EDGE_TYPE_ID"));
    json_object_array_add(e_obj, json_object_new_string("COUNT_PER_THREAD"));
    json_object_array_add(edges, e_obj);

    g_rw_lock_reader_lock(&bblock_htable_lock);

    GHashTableIter iter;
    Bblock_t *bb = NULL;
    EdgeData_t *e_data = NULL;
    uint64_t edge_id = 0;

    g_hash_table_iter_init(&iter, bblock_htable);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer*)&bb)) {

        g_rw_lock_reader_lock(&(bb->lock));

        for (int i = 0; i < bb->edges->len; i++) {
            e_data = &g_array_index(bb->edges, EdgeData_t, i);

            e_obj = json_object_new_array_ext(5);
            json_object_array_add(e_obj, json_object_new_uint64(++edge_id));
            json_object_array_add(e_obj, json_object_new_uint64(bb->bb_id));
            json_object_array_add(e_obj, json_object_new_uint64(e_data->dst_bb_id));
            json_object_array_add(e_obj, json_object_new_uint64(27));
            json_object *exec_obj = json_object_new_array_ext(qemu_plugin_num_vcpus());
            for (int vcpu_idx = 0; vcpu_idx < qemu_plugin_num_vcpus(); vcpu_idx++)
                json_object_array_add(exec_obj, json_object_new_uint64(qemu_plugin_u64_get(qemu_plugin_scoreboard_u64(e_data->count), vcpu_idx)));
            json_object_array_add(e_obj, exec_obj);
            json_object_array_add(edges, e_obj);
        }

        g_rw_lock_reader_unlock(&(bb->lock));
    }

    g_rw_lock_reader_unlock(&bblock_htable_lock);
}

static void process_data_mapping_to_json(pid_t pid, json_object *process_data)
{
    g_assert(json_object_is_type(process_data, json_type_object));

    /* Example:
     *  { "INSTR_COUNT" : 2134576,
     *    "INSTR_COUNT_PER_THREAD" : [ 1997750, 51676, 19794, 18381, 19598 ],
     *    "IMAGES" : [...],
     *    "EDGES" : [...]
     *  }
     */
    uint64_t total_n_ins = 0, thread_n_ins = 0;
    json_object *ins_obj = json_object_new_array_ext(qemu_plugin_num_vcpus());

    for (int vcpu_idx = 0; vcpu_idx < qemu_plugin_num_vcpus(); vcpu_idx++) {
        thread_n_ins = qemu_plugin_u64_get(n_insn, vcpu_idx);
        json_object_array_add(ins_obj, json_object_new_uint64(thread_n_ins));
        total_n_ins += thread_n_ins;
    }
    json_object_object_add(process_data,
                           "INSTR_COUNT", json_object_new_uint64(total_n_ins));
    json_object_object_add(process_data, "INSTR_COUNT_PER_THREAD", ins_obj);

    json_object *images_obj = json_object_new_array();
    images_mapping_to_json(pid, images_obj);
    json_object_object_add(process_data, "IMAGES", images_obj);

    json_object *edges_obj = json_object_new_array();
    edges_mapping_to_json(edges_obj);
    json_object_object_add(process_data, "EDGES", edges_obj);
}

static void processes_mapping_to_json(json_object *processes)
{
    g_assert(json_object_is_type(processes, json_type_array));

    /* Example:
     * "PROCESSES" :
     *  [ [ "PROCESS_ID", "PROCESS_DATA" ],
     *    [ 22814, {...} ],
     *    [ 958, {...} ]
     *  ]
     */
    json_object *p_obj = json_object_new_array_ext(2);
    json_object_array_add(p_obj, json_object_new_string("PROCESS_ID"));
    json_object_array_add(p_obj, json_object_new_string("PROCESS_DATA"));
    json_object_array_add(processes, p_obj);

    p_obj = json_object_new_array_ext(2);
    pid_t pid = getpid();
    json_object *pd_obj = json_object_new_object();
    process_data_mapping_to_json(pid, pd_obj);
    json_object_array_add(p_obj, json_object_new_uint64(pid));
    json_object_array_add(p_obj, pd_obj);

    json_object_array_add(processes, p_obj);
}

static void bbgraph_to_json(FILE *json_out_fd)
{
    g_assert(json_out_fd);

    /* Derived from SDE's format:
     *  https://www.intel.com/content/dam/develop/external/us/en/documents/dcfg-format-548994.pdf
     * Top-level object:
     *  { "MAJOR_VERSION" : 0,
     *    "MINOR_VERSION" : 6,
     *    "FILE_NAMES" : [...],
     *    "EDGE_TYPES" : [...],
     *    "SPECIAL_NODES" : [...],
     *    "PROCESSES" : [...],
     *  }
     */
    // Create a new JSON object (an empty object {})
    json_object *bbgraph_json = json_object_new_object();

    json_object_object_add(bbgraph_json,
                           "MAJOR_VERSION", json_object_new_uint64(0));
    json_object_object_add(bbgraph_json,
                           "MINOR_VERSION", json_object_new_uint64(1));

    json_object *FILE_NAMES = json_object_new_array();
    file_names_mapping_to_json(FILE_NAMES);
    json_object_object_add(bbgraph_json, "FILE_NAMES", FILE_NAMES);

    json_object *EDGE_TYPES = json_object_new_array();
    edge_types_mapping_to_json(EDGE_TYPES);
    json_object_object_add(bbgraph_json, "EDGE_TYPES", EDGE_TYPES);

    json_object *SPECIAL_NODES = json_object_new_array();
    special_nodes_mapping_to_json(SPECIAL_NODES);
    json_object_object_add(bbgraph_json, "SPECIAL_NODES", SPECIAL_NODES);

    json_object *PROCESSES = json_object_new_array();
    processes_mapping_to_json(PROCESSES);
    json_object_object_add(bbgraph_json, "PROCESSES", PROCESSES);

    // Convert the JSON object to a string
    const char *json_str = json_object_to_json_string_ext(
        bbgraph_json, (JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

    // Write the JSON string to the file
    fprintf(json_out_fd, "%s\n", json_str);

    // Free the JSON object memory
    json_object_put(bbgraph_json);
}

static void free_scoreboard_bb_data(void *data)
{
    qemu_plugin_scoreboard_free(((Bblock_t *)data)->count);
    g_free(data);
}

/* Called when we detect a linear execution (pc == pc_after_block). This means
 * a branch was avoided and we just transitioned from one to next block.
 *   ...and...
 * Called when we detect a non-linear execution (pc != pc_after_block). This
 * could be due to a fault causing some sort of exit exception (e.g. if cond
 * last_pc != block_end hits) or just a taken branch.
 */
static void vcpu_tb_branched_exec(unsigned int vcpu_idx, void *udata)
{
    Bblock_t *prev_bb = NULL;
    EdgeData_t *e_data = NULL;
    GArray *prev_bb_edges_list = NULL;

    uint64_t previous_bb_id = qemu_plugin_u64_get(prev_bb_id, vcpu_idx);
    uint64_t current_bb_id = *((uint64_t *)udata);

    /* return early for first block */
    if (!previous_bb_id)
	return;

    g_rw_lock_reader_lock(&bblock_htable_lock);
    prev_bb = g_hash_table_lookup(bblock_htable, (gconstpointer)previous_bb_id);
    g_assert(prev_bb);
    g_rw_lock_reader_unlock(&bblock_htable_lock);

    /* Check if we had this block-to-block transition before */
    g_rw_lock_reader_lock(&(prev_bb->lock));
    prev_bb_edges_list = prev_bb->edges;
    for (int i = 0; i < prev_bb_edges_list->len; i++)
        if (g_array_index(prev_bb_edges_list, EdgeData_t, i).dst_bb_id == current_bb_id)
            e_data = &g_array_index(prev_bb_edges_list, EdgeData_t, i);
    g_rw_lock_reader_unlock(&(prev_bb->lock));
    /* ...if we've never seen this before, then allocate a new entry */
    g_rw_lock_writer_lock(&(prev_bb->lock));
    if (!e_data) {
        EdgeData_t new_edge = { .dst_bb_id = current_bb_id };
	g_array_append_val(prev_bb_edges_list, new_edge);
	e_data = &g_array_index(prev_bb_edges_list, EdgeData_t, prev_bb_edges_list->len - 1);
	g_assert(e_data->dst_bb_id == current_bb_id);
	e_data->count = qemu_plugin_scoreboard_new(sizeof(uint64_t));
    }
    qemu_plugin_u64_add(qemu_plugin_scoreboard_u64(e_data->count), vcpu_idx, 1);
    g_rw_lock_writer_unlock(&(prev_bb->lock));
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    Bblock_t *bb = NULL;
    uint64_t bb_pc = qemu_plugin_tb_vaddr(tb);
    uint64_t bb_n_insns = qemu_plugin_tb_n_insns(tb);
    struct qemu_plugin_insn *first_insn = qemu_plugin_tb_get_insn(tb, 0);
    struct qemu_plugin_insn *last_insn = qemu_plugin_tb_get_insn(tb, bb_n_insns - 1);
    uint64_t bb_id = bb_pc ^ bb_n_insns;

    g_assert(bb_pc == qemu_plugin_insn_vaddr(first_insn)); //FIXME: is that so????

//    fprintf(stderr, "pc=0x%"PRIx64" bb_id=%"PRIu64" next=0x%"PRIx64"\n", bb_pc, bb_id, qemu_plugin_insn_vaddr(last_insn)+qemu_plugin_insn_size(last_insn));

    g_rw_lock_writer_lock(&bblock_htable_lock);
    bb = g_hash_table_lookup(bblock_htable, (gconstpointer)bb_id);
    if (!bb) {
        bb = g_new(Bblock_t, 1);
        g_assert(bb);
	g_rw_lock_init(&(bb->lock));
	bb->bb_id = bb_id;
        bb->table_idx = g_hash_table_size(bblock_htable);
        bb->vaddr = bb_pc;
        //for (bb->size = 0, int insn = 0; insn < bb_n_insns; insn++) bb->size += qemu_plugin_insn_size(qemu_plugin_tb_get_insn(tb, insn))
        bb->n_ins = bb_n_insns;
        //bb->vaddr_last_instr = bb_pc - qemu_plugin_insn_vaddr(last_insn);
        bb->count = qemu_plugin_scoreboard_new(sizeof(uint64_t));               // set to 0 internally
        bb->edges = g_array_new(true, true, sizeof(EdgeData_t));;
        g_hash_table_replace(bblock_htable, (gpointer)bb_id, bb);
    }
    g_rw_lock_writer_unlock(&bblock_htable_lock);

    /* Check if we are executing linearly after the last block or jumped. */
    qemu_plugin_register_vcpu_tb_exec_cond_cb(
        tb, vcpu_tb_branched_exec, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_COND_EQ, pc_after_bb, bb_pc, &(bb->bb_id));
    qemu_plugin_register_vcpu_tb_exec_cond_cb(
        tb, vcpu_tb_branched_exec, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_COND_NE, pc_after_bb, bb_pc, &(bb->bb_id));

    /* Now we can set start/end for this block so the next block can check
     * where we are at. Do this on the first instruction and not the TB so we
     * don't get mixed up with above.
     */
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64, prev_bb_id, bb_id);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64, pc_after_bb, qemu_plugin_insn_vaddr(last_insn) + qemu_plugin_insn_size(last_insn));

    /* Let's track the number of instructions executed by each vcpu, but if we
     * have early exits we might over-count...
     */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64, n_insn, bb_n_insns);
    /* and let's track the number of times this basicblock is executed.
     */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64, qemu_plugin_scoreboard_u64(bb->count), 1);
}

static void plugin_init(void)
{
    bblock_htable = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL,
                                          free_scoreboard_bb_data);

    /* score board declarations for the processor state */
    processor_state = qemu_plugin_scoreboard_new(sizeof(Vcpu_t));

    n_insn = qemu_plugin_scoreboard_u64_in_struct(
        processor_state, Vcpu_t, n_insn);
    prev_bb_id = qemu_plugin_scoreboard_u64_in_struct(
        processor_state, Vcpu_t, prev_bb_id);
    pc_after_bb = qemu_plugin_scoreboard_u64_in_struct(
        processor_state, Vcpu_t, pc_after_bb);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_autofree gchar *json_out_file = g_strdup_printf("%s.json", out_prefix);
    FILE *json_out_fd = fopen(json_out_file, "w");
    g_assert(json_out_fd);
    bbgraph_to_json(json_out_fd);
    fclose(json_out_fd);

    g_hash_table_unref(bblock_htable);
    g_free(out_prefix);
    qemu_plugin_scoreboard_free(processor_state);
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

    plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
