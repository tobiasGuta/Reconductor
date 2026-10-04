#include "validate.h"

#include <limits.h>
#include <string.h>
#include <sys/stat.h>

int exact_membership(const char *bytes, size_t length, char path[EXACT_PATH_CAP]) {
    if (length < 5U || length >= EXACT_PATH_CAP || memcmp(bytes, "0::/", 4U) != 0 ||
        bytes[length - 1U] != '\n') return 0;
    for (size_t i = 3U; i < length - 1U; i++) {
        unsigned char ch = (unsigned char)bytes[i];
        if (ch < 0x21U || ch > 0x7eU || ch == ':' || ch == '\\') return 0;
    }
    size_t n = length - 4U;
    memcpy(path, bytes + 3U, n);
    path[n] = '\0';
    return 1;
}

int exact_unit_path(const char *path) {
    const size_t prefix = sizeof(EXACT_PREFIX) - 1U;
    const size_t suffix = sizeof(EXACT_SUFFIX) - 1U;
    if (strlen(path) != prefix + 32U + suffix ||
        memcmp(path, EXACT_PREFIX, prefix) != 0 ||
        memcmp(path + prefix + 32U, EXACT_SUFFIX, suffix) != 0) return 0;
    for (size_t i = prefix; i < prefix + 32U; i++) {
        if (!((path[i] >= '0' && path[i] <= '9') ||
              (path[i] >= 'a' && path[i] <= 'f'))) return 0;
    }
    return 1;
}

int exact_domain(const char *bytes, size_t length) {
    return length == 7U && memcmp(bytes, "domain\n", 7U) == 0;
}

int exact_same_object(const struct statx *a, const struct statx *b) {
    const unsigned int needed = STATX_TYPE | STATX_INO | STATX_MNT_ID;
    return (a->stx_mask & needed) == needed && (b->stx_mask & needed) == needed &&
        a->stx_ino != 0U && a->stx_mnt_id != 0U &&
        a->stx_ino == b->stx_ino && a->stx_mnt_id == b->stx_mnt_id &&
        a->stx_dev_major == b->stx_dev_major && a->stx_dev_minor == b->stx_dev_minor &&
        a->stx_mode == b->stx_mode;
}

int exact_identity_parent(const struct statx *st) {
    const unsigned int needed = STATX_TYPE | STATX_MODE | STATX_UID | STATX_GID |
        STATX_INO | STATX_MNT_ID;
    return (st->stx_mask & needed) == needed && st->stx_ino != 0U && st->stx_mnt_id != 0U &&
        S_ISDIR(st->stx_mode) && st->stx_uid == 0U && st->stx_gid == 0U &&
        (st->stx_mode & (S_ISUID | S_ISGID | 0022U)) == 0U;
}

int exact_identity_anchor(const struct statx *st, const struct statx *runtime) {
    const unsigned int needed = STATX_TYPE | STATX_MODE | STATX_UID | STATX_GID |
        STATX_NLINK | STATX_INO | STATX_MNT_ID;
    return exact_identity_parent(runtime) && (st->stx_mask & needed) == needed &&
        st->stx_ino != 0U && S_ISREG(st->stx_mode) && st->stx_nlink == 1U &&
        st->stx_uid != 0U && st->stx_gid != 0U &&
        st->stx_uid != UINT32_MAX && st->stx_gid != UINT32_MAX &&
        (st->stx_mode & (S_ISUID | S_ISGID | 0022U)) == 0U &&
        st->stx_mnt_id == runtime->stx_mnt_id &&
        st->stx_dev_major == runtime->stx_dev_major && st->stx_dev_minor == runtime->stx_dev_minor;
}

int exact_same_identity_anchor(const struct statx *a, const struct statx *b) {
    const unsigned int needed = STATX_MODE | STATX_UID | STATX_GID | STATX_NLINK;
    return (a->stx_mask & needed) == needed && (b->stx_mask & needed) == needed &&
        exact_same_object(a, b) && a->stx_uid == b->stx_uid && a->stx_gid == b->stx_gid &&
        a->stx_nlink == b->stx_nlink;
}

static int decimal(const char *s, uint64_t *result) {
    uint64_t value = 0;
    if (*s == '\0') return 0;
    for (; *s != '\0'; s++) {
        if (*s < '0' || *s > '9') return 0;
        uint64_t digit = (uint64_t)(*s - '0');
        if (value > (UINT64_MAX - digit) / 10U) return 0;
        value = value * 10U + digit;
    }
    *result = value;
    return 1;
}

int exact_mount_line(struct exact_mounts *m, const char *bytes, size_t length) {
    char line[EXACT_MOUNT_LINE_CAP];
    char *fields[128];
    size_t count = 0;
    if (length < 2U || length >= sizeof line || bytes[length - 1U] != '\n') return 0;
    for (size_t i = 0; i < length - 1U; i++) {
        unsigned char ch = (unsigned char)bytes[i];
        if (ch < 0x20U || ch > 0x7eU) return 0;
    }
    memcpy(line, bytes, length - 1U);
    line[length - 1U] = '\0';
    char *start = line;
    for (char *p = line; ; p++) {
        if (*p == ' ' || *p == '\0') {
            int end = *p == '\0';
            if (p == start || count == sizeof fields / sizeof fields[0]) return 0;
            fields[count++] = start;
            *p = '\0';
            if (end) break;
            start = p + 1;
        }
    }
    if (count < 10U) return 0;
    size_t separator = 6U;
    while (separator < count && strcmp(fields[separator], "-") != 0) separator++;
    if (separator + 4U != count) return 0;
    uint64_t id, parent, major, minor;
    char *colon = strchr(fields[2], ':');
    if (colon == NULL) return 0;
    *colon = '\0';
    if (!decimal(fields[0], &id) || id == 0U || !decimal(fields[1], &parent) || parent == 0U ||
        !decimal(fields[2], &major) || !decimal(colon + 1, &minor) ||
        major > UINT32_MAX || minor > UINT32_MAX || fields[3][0] != '/' || fields[4][0] != '/') return 0;
    int proc = strcmp(fields[4], "/proc") == 0;
    int cgroup = strcmp(fields[4], "/sys/fs/cgroup") == 0;
    int runtime = m->runtime_id != 0U && strcmp(fields[4], "/run") == 0;
    if ((id == m->proc_id && !proc) || (id == m->cgroup_id && !cgroup) ||
        (m->runtime_id != 0U && id == m->runtime_id && !runtime)) return 0;
    /* A second cgroup2 mount is outside this deliberately narrow full-view
     * deployment contract, including a bind-mounted subtree. */
    if (strcmp(fields[separator + 1U], "cgroup2") == 0 && !cgroup) return 0;
    if (proc) {
        if (++m->proc_seen != 1U || id != m->proc_id || major != m->proc_major || minor != m->proc_minor ||
            strcmp(fields[3], "/") != 0 || strcmp(fields[separator + 1U], "proc") != 0) return 0;
    }
    if (cgroup) {
        if (++m->cgroup_seen != 1U || id != m->cgroup_id || major != m->cgroup_major || minor != m->cgroup_minor ||
            strcmp(fields[3], "/") != 0 || strcmp(fields[separator + 1U], "cgroup2") != 0) return 0;
    }
    if (runtime) {
        if (++m->runtime_seen != 1U || id != m->runtime_id || major != m->runtime_major ||
            minor != m->runtime_minor || strcmp(fields[3], "/") != 0 ||
            strcmp(fields[separator + 1U], "tmpfs") != 0) return 0;
    }
    return 1;
}

int exact_mounts_complete(const struct exact_mounts *m) {
    return m->proc_id != 0U && m->cgroup_id != 0U && m->proc_id != m->cgroup_id &&
        m->proc_seen == 1U && m->cgroup_seen == 1U &&
        (m->runtime_id == 0U || (m->runtime_id != m->proc_id &&
         m->runtime_id != m->cgroup_id && m->runtime_seen == 1U));
}
