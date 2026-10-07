#ifndef RECONDUCTOR_EXACT_CLEANUP_VALIDATE_H
#define RECONDUCTOR_EXACT_CLEANUP_VALIDATE_H

#include <stddef.h>
#include <stdint.h>
#include <linux/stat.h>

#define EXACT_PATH_CAP 256U
#define EXACT_MOUNT_LINE_CAP 4096U
#define EXACT_PREFIX "/reconductor.slice/reconductor-exact.slice/reconductor-exact-slot.slice/reconductor-exact-run@"
#define EXACT_SUFFIX ".service"

/* Pure validation only; none of these functions opens a path or issues evidence. */
int exact_membership(const char *bytes, size_t length, char path[EXACT_PATH_CAP]);
int exact_unit_path(const char *path);
int exact_domain(const char *bytes, size_t length);
int exact_same_object(const struct statx *a, const struct statx *b);
int exact_identity_parent(const struct statx *st);
int exact_identity_anchor(const struct statx *st, const struct statx *runtime);
int exact_same_identity_anchor(const struct statx *a, const struct statx *b);

struct exact_mounts {
    uint64_t proc_id, cgroup_id;
    uint32_t proc_major, proc_minor, cgroup_major, cgroup_minor;
    unsigned int proc_seen, cgroup_seen;
    uint64_t runtime_id;
    uint32_t runtime_major, runtime_minor;
    unsigned int runtime_seen;
};
/* Consume one newline-terminated kernel mountinfo line. Reject malformed input,
 * duplicate fixed anchors, mismatched IDs/devices and non-root anchor mounts. */
int exact_mount_line(struct exact_mounts *mounts, const char *bytes, size_t length);
int exact_mounts_complete(const struct exact_mounts *mounts);

#endif
