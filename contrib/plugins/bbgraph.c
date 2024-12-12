/*
 * Extract basic block graphs for Machine Code analysis tools.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <glib.h>
#include <assert.h>

#include "qemu-plugin.h"

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
static char *filename_prefix;
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
    g_free(filename_prefix);
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

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    g_autofree gchar *vcpu_filename = NULL;

    vcpu_filename = g_strdup_printf("%s.%u.bb", filename_prefix, vcpu_index);
    Vcpu_t *vcpu = qemu_plugin_scoreboard_find(vcpus, vcpu_index);
    vcpu->file = fopen(vcpu_filename, "w");

    assert(vcpu->file);
}

static void vcpu_exit(unsigned int vcpu_index, void *udata)
{
    Vcpu_t *vcpu = qemu_plugin_scoreboard_find(vcpus, vcpu_index);
    GHashTableIter iter;
    void *value;

    if (!vcpu->file) {
        return;
    }

    fputc('T', vcpu->file);

    g_rw_lock_reader_lock(&bblock_htable_lock);
    g_hash_table_iter_init(&iter, bblock_htable);

    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        Bblock_t *bb = value;
        uint64_t bb_count = qemu_plugin_u64_get(bb_count_u64(bb), vcpu_index);

        if (!bb_count) {
            continue;
        }

        fprintf(vcpu->file, ":%u:%" PRIu64 " ", bb->index, bb_count);
        qemu_plugin_u64_set(bb_count_u64(bb), vcpu_index, 0);
    }

    g_rw_lock_reader_unlock(&bblock_htable_lock);
    fputc('\n', vcpu->file);

    fclose(vcpu->file);
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
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "outfile") == 0) {
            filename_prefix = tokens[1];
            tokens[1] = NULL;
        } else {
            fprintf(stderr, "ERR: option parsing failed: %s\n", opt);
            return -1;
        }
    }

    if (!filename_prefix) {
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
