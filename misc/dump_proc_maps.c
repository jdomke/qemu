#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
static void dump_proc_maps_after_main(void) __attribute__((destructor));
static void dump_proc_maps_after_main(void) {
    FILE *pidmap_in_file, *pidmap_out_file;
    char fn[128];

    snprintf(fn, sizeof(fn), "/tmp/%d.dpm", getpid());
    if (!(pidmap_out_file = fopen(fn, "w")))
        return;

    snprintf(fn, sizeof(fn), "/proc/%d/maps", getpid());
    if (!(pidmap_in_file = fopen(fn, "r")))
        return;

    char line[128+(128+256)];
    uint64_t start, end;
    char perms[5], offset[9], dev[6], inode[11];
    char filepath[128+256];

    while (fgets(line, sizeof(line), pidmap_in_file)) {
        // parse the line for start, end, permissions, offset, etc.
        if (sscanf(line, "%lx-%lx %4s %8s %5s %10s %255s",
                   &start, &end, perms, offset, dev, inode, filepath) >= 6) {
            fprintf(pidmap_out_file, "%s", line);
        }
    }

    fclose(pidmap_in_file);
    fclose(pidmap_out_file);
}
