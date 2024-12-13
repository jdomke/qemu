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

static void plugin_exit(qemu_plugin_id_t id, void *p);
static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index);
static void vcpu_exit(unsigned int vcpu_index, void *udata);
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);
static void free_scoreboard_bb_data(void *data);
static qemu_plugin_u64 bb_count_u64(Bblock_t *bb);

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    for (int i = 0; i < qemu_plugin_num_vcpus(); i++)
        vcpu_exit(i, NULL);

    g_hash_table_unref(bblock_htable);
    g_free(out_prefix);
    qemu_plugin_scoreboard_free(vcpus);
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

static void virtaddrspace_mapping_to_json(json_object *vaddr_map) {
    FILE *file = fopen("/proc/self/maps", "r");
    assert(file);

    char line[128+(128+256)];
    uint64_t start, end, i = 1;
    char perms[5], offset[9], dev[6], inode[11];
    char pathname[128+256];

    json_object *map_obj = json_object_new_array();
    json_object_array_add(map_obj, json_object_new_string("FILE_NAME_ID"));
    json_object_array_add(map_obj, json_object_new_string("FILE_NAME"));
    json_object_array_add(map_obj, json_object_new_string("START"));            // uint64 of the hex pc
    json_object_array_add(map_obj, json_object_new_string("END"));              // uint64 of the hex pc
    json_object_array_add(map_obj, json_object_new_string("PERMISSIONS"));
    json_object_array_add(map_obj, json_object_new_string("OFFSET"));
    json_object_array_add(map_obj, json_object_new_string("DEVICE"));
    json_object_array_add(map_obj, json_object_new_string("INODE"));
    json_object_array_add(vaddr_map, map_obj);

    while (fgets(line, sizeof(line), file)) {
        // parse the line for start, end, permissions, offset, etc.
        if (sscanf(line, "%lx-%lx %4s %8s %5s %10s %255s",
                   &start, &end, perms, offset, dev, inode, pathname) >= 6) {
            if (perms[0] == 'r' && perms[1] != 'w') {
                //fprintf(stderr,
                //        "start: 0x%lx, end: 0x%lx, permissions: %s, path: %s\n",
                //        start, end, perms, pathname);

                // Create a new JSON object for this mapping
                map_obj = json_object_new_array();
                // Add key-value pairs to the JSON object
                json_object_array_add(map_obj, json_object_new_uint64(i));
                json_object_array_add(map_obj, json_object_new_string(pathname));
                json_object_array_add(map_obj, json_object_new_uint64(start));
                json_object_array_add(map_obj, json_object_new_uint64(end));
                json_object_array_add(map_obj, json_object_new_string(perms));
                json_object_array_add(map_obj, json_object_new_string(offset));
                json_object_array_add(map_obj, json_object_new_string(dev));
                json_object_array_add(map_obj, json_object_new_string(inode));
                // Add this JSON object to the JSON array
                json_object_array_add(vaddr_map, map_obj);

		i++;
            }
        }
    }
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
//    Vcpu_t *vcpu = qemu_plugin_scoreboard_find(vcpus, vcpu_index);
}

static void vcpu_exit(unsigned int vcpu_index, void *udata)
{
    //Vcpu_t *vcpu = qemu_plugin_scoreboard_find(vcpus, vcpu_index);
    GHashTableIter iter;
    void *value;

    g_autofree gchar *json_out_file = g_strdup_printf("%s.json", out_prefix);
    FILE *json_out_fd = NULL;
    if (!vcpu_index)
        json_out_fd = fopen(json_out_file, "w");
    else
        json_out_fd = fopen(json_out_file, "a");

    if (!json_out_fd)
        return;

    // Create a new JSON object (an empty object {})
    json_object *bbgraph_json = json_object_new_object();
    json_object_object_add(bbgraph_json, "MAJOR_VERSION", json_object_new_uint64(1));
    json_object_object_add(bbgraph_json, "MINOR_VERSION", json_object_new_uint64(0));

    json_object *virtaddspace = json_object_new_array();
    virtaddrspace_mapping_to_json(virtaddspace);
    json_object_object_add(bbgraph_json, "FILE_NAMES", virtaddspace);

    // Convert the JSON object to a string
    const char *json_str = json_object_to_json_string_ext(bbgraph_json,
	                                                  (JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

    // Write the JSON string to the file
    fprintf(json_out_fd, "%s\n", json_str);

    g_rw_lock_reader_lock(&bblock_htable_lock);
    g_hash_table_iter_init(&iter, bblock_htable);

    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        Bblock_t *bb = value;
        uint64_t bb_count = qemu_plugin_u64_get(bb_count_u64(bb), vcpu_index);

        if (!bb_count) {
            continue;
        }

        fprintf(json_out_fd, ":%u:%" PRIu64 " ", bb->index, bb_count);
        qemu_plugin_u64_set(bb_count_u64(bb), vcpu_index, 0);
    }

    g_rw_lock_reader_unlock(&bblock_htable_lock);
    fputc('\n', json_out_fd);

    fclose(json_out_fd);

    // Free the JSON object memory
    json_object_put(bbgraph_json);
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
