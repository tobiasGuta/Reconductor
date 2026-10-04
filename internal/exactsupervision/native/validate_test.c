#define _GNU_SOURCE
#include "validate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static unsigned int checks;
#define CHECK(x) do { checks++; if (!(x)) { fputs("validator test failed\n", stderr); exit(1); } } while (0)

static const char valid[] = EXACT_PREFIX "0123456789abcdef0123456789abcdef" EXACT_SUFFIX;

static void paths(void) {
    char path[EXACT_PATH_CAP], membership[EXACT_PATH_CAP];
    int n = snprintf(membership, sizeof membership, "0::%s\n", valid);
    CHECK(n > 0 && (size_t)n < sizeof membership);
    CHECK(exact_membership(membership, (size_t)n, path));
    CHECK(strcmp(path, valid) == 0 && exact_unit_path(path));
    CHECK(exact_unit_path(EXACT_PREFIX "00000000000000000000000000000000" EXACT_SUFFIX));
    static const char *const bad[] = {
        "", "/", "/reconductor.slice", "/reconductor.slice/reconductor-exact.slice",
        "/reconductor.slice/reconductor-exact.slice/reconductor-exact-slot.slice",
        "/system.slice", "/system.slice/other.service",
        "/reconductor-exact-slot.slice/reconductor-exact-run@0123456789abcdef0123456789abcdef.service",
        EXACT_PREFIX "0123456789abcdef0123456789abcdef.slice",
        EXACT_PREFIX "0123456789abcdef0123456789abcdef.service/child",
        EXACT_PREFIX "0123456789abcdef0123456789abcdef.service/../other.service",
        EXACT_PREFIX "0123456789abcdef0123456789abcdef.service/",
        EXACT_PREFIX "0123456789abcdef0123456789abcde.service",
        EXACT_PREFIX "0123456789abcdef0123456789abcdef0.service",
        EXACT_PREFIX "0123456789abcdef0123456789abcdeg.service",
        EXACT_PREFIX "0123456789ABCDEF0123456789ABCDEF.service",
        EXACT_PREFIX "0123456789abcdef0123456789abcde/.service",
        EXACT_PREFIX "0123456789abcdef0123456789abcde\\.service",
        EXACT_PREFIX "0123456789abcdef0123456789abcdef.service (deleted)",
        "/reconductor.slice/../reconductor-exact.slice/reconductor-exact-slot.slice/reconductor-exact-run@0123456789abcdef0123456789abcdef.service",
        "/reconductor.slice//reconductor-exact.slice/reconductor-exact-slot.slice/reconductor-exact-run@0123456789abcdef0123456789abcdef.service",
        "/reconductor.slice/reconductor-exact.slice/reconductor-exact-slot.slice/other@0123456789abcdef0123456789abcdef.service"
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) CHECK(!exact_unit_path(bad[i]));
    static const char *const malformed[] = {
        "", "0::/", "0::\n", "0::relative\n", "1::/\n", "00::/\n",
        "1:cpu:/somewhere\n", "0:cpu:/somewhere\n", "0::/\n0::/\n",
        "0::/\n1:cpu:/\n", "1:cpu:/\n0::/\n", "0::/\n\n",
        "0::/somewhere\r\n", "0::/some where\n", "0::/\\x2f\n", "0::/path:extra\n"
    };
    for (size_t i = 0; i < sizeof malformed / sizeof malformed[0]; i++) {
        CHECK(!exact_membership(malformed[i], strlen(malformed[i]), path));
    }
    CHECK(exact_membership("0::/\n", 5U, path) && !exact_unit_path(path));
    static const char nul[] = "0::/good\0hidden\n";
    CHECK(!exact_membership(nul, sizeof nul - 1U, path));
    char long_input[EXACT_PATH_CAP + 1U];
    memset(long_input, 'a', sizeof long_input);
    memcpy(long_input, "0::/", 4U);
    long_input[sizeof long_input - 1U] = '\n';
    CHECK(!exact_membership(long_input, sizeof long_input, path));
}

static struct exact_mounts mounts(void) {
    struct exact_mounts m = {.proc_id = 20, .cgroup_id = 30, .proc_minor = 5, .cgroup_minor = 6};
    return m;
}
static int line(struct exact_mounts *m, const char *s) { return exact_mount_line(m, s, strlen(s)); }

static void mount_views(void) {
    static const char proc[] = "20 10 0:5 / /proc rw,nosuid,nodev,noexec - proc proc rw\n";
    static const char cgroup[] = "30 10 0:6 / /sys/fs/cgroup rw,nosuid,nodev,noexec shared:5 - cgroup2 cgroup2 rw\n";
    struct exact_mounts m = mounts();
    CHECK(!exact_mounts_complete(&m));
    CHECK(line(&m, "10 1 8:1 / / rw - ext4 /dev/sda rw\n"));
    CHECK(line(&m, proc) && !exact_mounts_complete(&m));
    CHECK(line(&m, cgroup) && exact_mounts_complete(&m));
    CHECK(!line(&m, proc));
    m = mounts();
    CHECK(line(&m, cgroup) && !line(&m, cgroup));
    static const char *const bad[] = {
        "20 10 0:5 /subtree /proc rw - proc proc rw\n",
        "20 10 0:5 /\\040 /proc rw - proc proc rw\n",
        "21 10 0:5 / /proc rw - proc proc rw\n",
        "20 10 0:7 / /proc rw - proc proc rw\n",
        "20 10 1:5 / /proc rw - proc proc rw\n",
        "20 10 0:5 / /proc rw - tmpfs tmpfs rw\n",
        "30 10 0:6 /child /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
        "30 10 0:6 / /sys/fs/cgroup rw - cgroup cgroup rw\n",
        "30 10 0:6 / /elsewhere rw - cgroup2 cgroup2 rw\n",
        "31 10 0:6 / /elsewhere rw - cgroup2 cgroup2 rw\n",
        "20 10 0:5 / /elsewhere rw - proc proc rw\n",
        "20 10 0:5 / /proc rw - proc proc rw",
        "20 10 0:5 / /proc rw - proc proc rw\n\n",
        "20 10 0:5 / /proc rw - proc proc rw extra\n",
        "20 10 0:5 / /proc rw proc proc rw\n",
        "0 10 0:5 / /proc rw - proc proc rw\n",
        "20 0 0:5 / /proc rw - proc proc rw\n",
        "20 10 4294967296:5 / /proc rw - proc proc rw\n",
        "20 10 0:4294967296 / /proc rw - proc proc rw\n",
        "18446744073709551616 10 0:5 / /proc rw - proc proc rw\n",
        "20 10 0:5 / /proc  rw - proc proc rw\n",
        "20 10 0:5 / /proc rw - proc proc rw \n"
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        m = mounts();
        CHECK(!line(&m, bad[i]));
    }
    static const char nul[] = "20 10 0:5 / /proc rw - proc\0x proc rw\n";
    m = mounts();
    CHECK(!exact_mount_line(&m, nul, sizeof nul - 1U));
    char too_long[EXACT_MOUNT_LINE_CAP];
    memset(too_long, 'a', sizeof too_long);
    too_long[sizeof too_long - 1U] = '\n';
    CHECK(!exact_mount_line(&m, too_long, sizeof too_long));
    m = mounts();
    m.cgroup_id = m.proc_id;
    CHECK(!exact_mounts_complete(&m));
}

static void identities_and_type(void) {
    CHECK(exact_domain("domain\n", 7U));
    static const char *const bad[] = {"", "domain", "domain\n\n", "domain threaded\n", "threaded\n", "domain (invalid)\n", "domain\r\n"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) CHECK(!exact_domain(bad[i], strlen(bad[i])));
    struct statx a = {.stx_mask = STATX_TYPE | STATX_INO | STATX_MNT_ID, .stx_ino = 42,
                     .stx_mnt_id = 30, .stx_dev_minor = 6, .stx_mode = S_IFDIR | 0755};
    CHECK(exact_same_object(&a, &a));
    struct statx b = a;
    b.stx_ino++; CHECK(!exact_same_object(&a, &b));
    b = a; b.stx_mnt_id++; CHECK(!exact_same_object(&a, &b));
    b = a; b.stx_dev_major++; CHECK(!exact_same_object(&a, &b));
    b = a; b.stx_dev_minor++; CHECK(!exact_same_object(&a, &b));
    b = a; b.stx_mode = S_IFREG | 0644; CHECK(!exact_same_object(&a, &b));
    b = a; b.stx_mask &= ~STATX_MNT_ID; CHECK(!exact_same_object(&a, &b));
    b = a; b.stx_ino = 0; CHECK(!exact_same_object(&b, &b));
    b = a; b.stx_mnt_id = 0; CHECK(!exact_same_object(&b, &b));
    struct statx zero = {0}; CHECK(!exact_same_object(&zero, &zero));
}

static void identity_anchors(void) {
    struct statx parent = {.stx_mask = STATX_TYPE | STATX_MODE | STATX_UID | STATX_GID |
        STATX_NLINK | STATX_INO | STATX_MNT_ID, .stx_ino = 100, .stx_mnt_id = 40,
        .stx_dev_minor = 7, .stx_mode = S_IFDIR | 0755, .stx_nlink = 2};
    struct statx file = parent;
    file.stx_mode = S_IFREG | 0600;
    file.stx_uid = 123456U;
    file.stx_gid = 234567U;
    file.stx_nlink = 1;
    file.stx_ino++;
    CHECK(exact_identity_parent(&parent));
    CHECK(exact_identity_anchor(&file, &parent));
    CHECK(exact_same_identity_anchor(&file, &file));
    struct statx changed = file;
    changed.stx_mode = S_IFREG | 0644; CHECK(exact_identity_anchor(&changed, &parent));
    changed = file; changed.stx_uid = 0; CHECK(!exact_identity_anchor(&changed, &parent));
    changed = file; changed.stx_gid = 0; CHECK(!exact_identity_anchor(&changed, &parent));
    changed = file; changed.stx_uid = UINT32_MAX; CHECK(!exact_identity_anchor(&changed, &parent));
    changed = file; changed.stx_gid = UINT32_MAX; CHECK(!exact_identity_anchor(&changed, &parent));
    static const unsigned int unsafe_modes[] = {
        S_IFDIR | 0600U, S_IFLNK | 0600U, S_IFIFO | 0600U, S_IFCHR | 0600U,
        S_IFSOCK | 0600U, S_IFREG | S_ISUID | 0600U, S_IFREG | S_ISGID | 0600U,
        S_IFREG | 0620U, S_IFREG | 0602U
    };
    for (size_t i = 0; i < sizeof unsafe_modes / sizeof unsafe_modes[0]; i++) {
        changed = file; changed.stx_mode = (uint16_t)unsafe_modes[i];
        CHECK(!exact_identity_anchor(&changed, &parent));
    }
    changed = file; changed.stx_nlink = 0; CHECK(!exact_identity_anchor(&changed, &parent));
    changed = file; changed.stx_nlink = 2; CHECK(!exact_identity_anchor(&changed, &parent));
    changed = file; changed.stx_mnt_id++; CHECK(!exact_identity_anchor(&changed, &parent));
    changed = file; changed.stx_dev_major++; CHECK(!exact_identity_anchor(&changed, &parent));
    changed = file; changed.stx_dev_minor++; CHECK(!exact_identity_anchor(&changed, &parent));
    changed = file; changed.stx_ino = 0; CHECK(!exact_identity_anchor(&changed, &parent));
    static const unsigned int required[] = {STATX_TYPE, STATX_MODE, STATX_UID, STATX_GID,
        STATX_NLINK, STATX_INO, STATX_MNT_ID};
    for (size_t i = 0; i < sizeof required / sizeof required[0]; i++) {
        changed = file; changed.stx_mask &= ~required[i];
        CHECK(!exact_identity_anchor(&changed, &parent));
    }
    changed = parent; changed.stx_uid = 1; CHECK(!exact_identity_parent(&changed));
    CHECK(!exact_identity_anchor(&file, &changed));
    changed = parent; changed.stx_gid = 1; CHECK(!exact_identity_parent(&changed));
    changed = parent; changed.stx_mode |= 0020U; CHECK(!exact_identity_parent(&changed));
    changed = parent; changed.stx_mode |= 0002U; CHECK(!exact_identity_parent(&changed));
    changed = parent; changed.stx_mode |= S_ISGID; CHECK(!exact_identity_parent(&changed));
    changed = parent; changed.stx_mode |= S_ISUID; CHECK(!exact_identity_parent(&changed));
    changed = parent; changed.stx_mode = S_IFREG | 0755; CHECK(!exact_identity_parent(&changed));
    changed = parent; changed.stx_mask &= ~STATX_GID; CHECK(!exact_identity_parent(&changed));
    changed = parent; changed.stx_mnt_id = 0; CHECK(!exact_identity_parent(&changed));
    changed = file; changed.stx_uid++; CHECK(!exact_same_identity_anchor(&file, &changed));
    changed = file; changed.stx_gid++; CHECK(!exact_same_identity_anchor(&file, &changed));
    changed = file; changed.stx_nlink++; CHECK(!exact_same_identity_anchor(&file, &changed));
    changed = file; changed.stx_ino++; CHECK(!exact_same_identity_anchor(&file, &changed));
    changed = file; changed.stx_mode++; CHECK(!exact_same_identity_anchor(&file, &changed));
    changed = file; changed.stx_mask &= ~STATX_UID; CHECK(!exact_same_identity_anchor(&file, &changed));
    changed = file; changed.stx_mask &= ~STATX_MODE; CHECK(!exact_same_identity_anchor(&file, &changed));
}

static void runtime_views(void) {
    static const char *const bad[] = {
        "40 10 0:7 /subtree /run rw - tmpfs tmpfs rw\n",
        "41 10 0:7 / /run rw - tmpfs tmpfs rw\n",
        "40 10 0:8 / /run rw - tmpfs tmpfs rw\n",
        "40 10 1:7 / /run rw - tmpfs tmpfs rw\n",
        "40 10 0:7 / /run rw - ext4 /dev/sda rw\n",
        "40 10 0:7 / /elsewhere rw - tmpfs tmpfs rw\n"
    };
    struct exact_mounts m = mounts();
    m.runtime_id = 40; m.runtime_minor = 7;
    CHECK(line(&m, "20 10 0:5 / /proc rw - proc proc rw\n"));
    CHECK(line(&m, "30 10 0:6 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"));
    CHECK(!exact_mounts_complete(&m));
    CHECK(line(&m, "40 10 0:7 / /run rw - tmpfs tmpfs rw\n"));
    CHECK(exact_mounts_complete(&m));
    CHECK(!line(&m, "40 10 0:7 / /run rw - tmpfs tmpfs rw\n"));
    m.runtime_id = m.proc_id; CHECK(!exact_mounts_complete(&m));
    m.runtime_id = m.cgroup_id; CHECK(!exact_mounts_complete(&m));
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        m = mounts(); m.runtime_id = 40; m.runtime_minor = 7;
        CHECK(!line(&m, bad[i]));
    }
}

static void bounded_bytes(void) {
    /* Deterministic malformed-byte coverage for ASan/UBSan; no host syscalls. */
    uint32_t seed = 12345U;
    char bytes[EXACT_MOUNT_LINE_CAP], path[EXACT_PATH_CAP];
    for (unsigned int iteration = 0; iteration < 20000U; iteration++) {
        seed = seed * 1664525U + 1013904223U;
        size_t n = (size_t)(seed % (uint32_t)sizeof bytes);
        for (size_t i = 0; i < n; i++) {
            seed = seed * 1664525U + 1013904223U;
            bytes[i] = (char)(seed >> 24);
        }
        int accepted = exact_membership(bytes, n, path);
        if (accepted) CHECK(strlen(path) < EXACT_PATH_CAP);
        struct exact_mounts m = mounts();
        (void)exact_mount_line(&m, bytes, n);
        (void)exact_domain(bytes, n);
    }
}

int main(void) {
    paths();
    mount_views();
    identities_and_type();
    identity_anchors();
    runtime_views();
    bounded_bytes();
    printf("PASS: %u assertions and 20000 bounded parser inputs; no cgroup writes\n", checks);
    return 0;
}
