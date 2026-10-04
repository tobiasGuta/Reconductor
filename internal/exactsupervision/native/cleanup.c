/* Linux-only own-cgroup cleanup. Never run this binary in a host test harness.
 * There are no test target overrides, configuration-content readers or subprocesses. */
#define _GNU_SOURCE
#include "validate.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <linux/securebits.h>
#include <stdio.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

enum failure {
    INVALID_ARGUMENTS = 1, PROCFS = 2, CGROUP2 = 3, MEMBERSHIP = 4,
    UNIT_SHAPE = 5, PATH_VALIDATION = 6, OPENAT2 = 7, IDENTITY = 8,
    KILL_OPEN = 9, KILL_WRITE = 10, CGROUP_TYPE = 11,
    PRIVILEGE = 12, FD_HYGIENE = 13, WRITE_RETURNED = 14,
    IDENTITY_ANCHOR = 15, CREDENTIAL_TRANSITION = 16, FINAL_CREDENTIALS = 17
};

#define LOCKED_SECUREBITS (SECBIT_KEEP_CAPS_LOCKED | SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | \
    SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED | \
    SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED)

struct drop_anchor {
    int runtime, parent, file;
    struct statx root_id, runtime_id, parent_id, file_id;
};

static void __attribute__((noreturn)) fail(enum failure code) { _exit((int)code); }

static int beneath(int parent, const char *path, int flags, int same_mount, enum failure code) {
    struct open_how how = {
        .flags = (unsigned long long)(unsigned int)(flags | O_CLOEXEC | O_NOFOLLOW),
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
    };
    if (same_mount) how.resolve |= RESOLVE_NO_XDEV;
    int fd = (int)syscall(SYS_openat2, parent, path, &how, sizeof how);
    if (fd < 0) {
        if (errno == ENOSYS || errno == EINVAL || errno == E2BIG || errno == EOPNOTSUPP) fail(OPENAT2);
        if (errno == ELOOP || errno == EXDEV) fail(PATH_VALIDATION);
        fail(code);
    }
    return fd;
}

static struct statx identity(int fd, int directory, long magic, enum failure code) {
    struct statx st = {0};
    struct statfs fs;
    const unsigned int needed = STATX_TYPE | STATX_MODE | STATX_UID | STATX_INO | STATX_MNT_ID;
    if (fstatfs(fd, &fs) != 0 || fs.f_type != magic ||
        statx(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, needed, &st) != 0 ||
        (st.stx_mask & needed) != needed || st.stx_ino == 0U || st.stx_mnt_id == 0U ||
        st.stx_uid != 0U || (st.stx_mode & 0022U) != 0U ||
        (directory ? !S_ISDIR(st.stx_mode) : !S_ISREG(st.stx_mode))) fail(code);
    return st;
}

static struct statx anchor_metadata(int fd, int runtime_fs) {
    struct statx st = {0};
    struct statfs fs;
    const unsigned int needed = STATX_TYPE | STATX_MODE | STATX_UID | STATX_GID |
        STATX_NLINK | STATX_INO | STATX_MNT_ID;
    if (statx(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, needed, &st) != 0 ||
        (st.stx_mask & needed) != needed ||
        (runtime_fs && (fstatfs(fd, &fs) != 0 || fs.f_type != TMPFS_MAGIC))) fail(IDENTITY_ANCHOR);
    return st;
}

static struct drop_anchor pin_drop_anchor(int root) {
    struct drop_anchor a;
    a.root_id = anchor_metadata(root, 0);
    if (!exact_identity_parent(&a.root_id)) fail(IDENTITY_ANCHOR);
    /* Only the fixed /run mount crossing is allowed. Below it NO_XDEV is
     * mandatory, including for the contents-ignored O_PATH identity inode. */
    a.runtime = beneath(root, "run", O_PATH | O_DIRECTORY, 0, IDENTITY_ANCHOR);
    a.runtime_id = anchor_metadata(a.runtime, 1);
    a.parent = beneath(a.runtime, "reconductor-exact", O_PATH | O_DIRECTORY, 1, IDENTITY_ANCHOR);
    a.parent_id = anchor_metadata(a.parent, 1);
    if (!exact_identity_parent(&a.runtime_id) || !exact_identity_parent(&a.parent_id) ||
        a.parent_id.stx_mnt_id != a.runtime_id.stx_mnt_id ||
        a.parent_id.stx_dev_major != a.runtime_id.stx_dev_major ||
        a.parent_id.stx_dev_minor != a.runtime_id.stx_dev_minor) fail(IDENTITY_ANCHOR);
    a.file = beneath(a.parent, "execution.identity", O_PATH, 1, IDENTITY_ANCHOR);
    a.file_id = anchor_metadata(a.file, 1);
    if (!exact_identity_anchor(&a.file_id, &a.runtime_id)) fail(IDENTITY_ANCHOR);
    return a;
}

static void recheck_drop_anchor(int root, const struct drop_anchor *a) {
    struct statx st = anchor_metadata(root, 0);
    if (!exact_identity_parent(&st) || !exact_same_object(&a->root_id, &st)) fail(IDENTITY_ANCHOR);
    int run = beneath(root, "run", O_PATH | O_DIRECTORY, 0, IDENTITY_ANCHOR);
    st = anchor_metadata(run, 1);
    if (!exact_identity_parent(&st) || !exact_same_object(&a->runtime_id, &st)) fail(IDENTITY_ANCHOR);
    int parent = beneath(run, "reconductor-exact", O_PATH | O_DIRECTORY, 1, IDENTITY_ANCHOR);
    st = anchor_metadata(parent, 1);
    if (!exact_identity_parent(&st) || !exact_same_object(&a->parent_id, &st)) fail(IDENTITY_ANCHOR);
    int file = beneath(parent, "execution.identity", O_PATH, 1, IDENTITY_ANCHOR);
    st = anchor_metadata(file, 1);
    if (!exact_identity_anchor(&st, &a->runtime_id) ||
        !exact_same_identity_anchor(&a->file_id, &st)) fail(IDENTITY_ANCHOR);
    st = anchor_metadata(a->file, 1);
    if (!exact_identity_anchor(&st, &a->runtime_id) ||
        !exact_same_identity_anchor(&a->file_id, &st)) fail(IDENTITY_ANCHOR);
    if (close(file) != 0 || close(parent) != 0 || close(run) != 0) fail(IDENTITY_ANCHOR);
}

static int file_in(int parent, const char *name, int flags, const struct statx *anchor,
                   long magic, enum failure code) {
    int fd = beneath(parent, name, flags, 1, code);
    struct statx st = identity(fd, 0, magic, code);
    if (st.stx_mnt_id != anchor->stx_mnt_id || st.stx_dev_major != anchor->stx_dev_major ||
        st.stx_dev_minor != anchor->stx_dev_minor) fail(PATH_VALIDATION);
    return fd;
}

static size_t read_small(int fd, char *bytes, size_t capacity, enum failure code) {
    size_t used = 0;
    for (;;) {
        if (used == capacity) fail(code);
        ssize_t n = read(fd, bytes + used, capacity - used);
        if (n < 0) {
            if (errno == EINTR) continue;
            fail(code);
        }
        if (n == 0) return used;
        used += (size_t)n;
    }
}

static void membership(int pid_dir, const struct statx *proc, char path[EXACT_PATH_CAP]) {
    char bytes[EXACT_PATH_CAP];
    int fd = file_in(pid_dir, "cgroup", O_RDONLY, proc, PROC_SUPER_MAGIC, MEMBERSHIP);
    size_t n = read_small(fd, bytes, sizeof bytes, MEMBERSHIP);
    if (close(fd) != 0 || !exact_membership(bytes, n, path)) fail(MEMBERSHIP);
    if (!exact_unit_path(path)) fail(UNIT_SHAPE);
}

static void mount_view(int pid_dir, const struct statx *proc, const struct statx *cg,
                       const struct statx *runtime) {
    struct exact_mounts m = {
        .proc_id = proc->stx_mnt_id, .cgroup_id = cg->stx_mnt_id,
        .proc_major = proc->stx_dev_major, .proc_minor = proc->stx_dev_minor,
        .cgroup_major = cg->stx_dev_major, .cgroup_minor = cg->stx_dev_minor
    };
    if (runtime != NULL) {
        m.runtime_id = runtime->stx_mnt_id;
        m.runtime_major = runtime->stx_dev_major;
        m.runtime_minor = runtime->stx_dev_minor;
    }
    int fd = file_in(pid_dir, "mountinfo", O_RDONLY, proc, PROC_SUPER_MAGIC, PATH_VALIDATION);
    char chunk[4096], line[EXACT_MOUNT_LINE_CAP];
    size_t used = 0, total = 0;
    for (;;) {
        ssize_t n = read(fd, chunk, sizeof chunk);
        if (n < 0) {
            if (errno == EINTR) continue;
            fail(PATH_VALIDATION);
        }
        if (n == 0) break;
        total += (size_t)n;
        if (total > 1048576U) fail(PATH_VALIDATION);
        for (size_t i = 0; i < (size_t)n; i++) {
            if (used == sizeof line) fail(PATH_VALIDATION);
            line[used++] = chunk[i];
            if (chunk[i] == '\n') {
                if (!exact_mount_line(&m, line, used)) fail(PATH_VALIDATION);
                used = 0;
            }
        }
    }
    if (close(fd) != 0 || used != 0U || !exact_mounts_complete(&m)) fail(PATH_VALIDATION);
}

/* These are kernel-generated namespace link TEXTS, not links opened/followed.
 * Reject a cgroup/user/PID namespace different from the validated proc PID1.
 * Full-root mount validation and the non-root-file absence check below are
 * also required: namespace-relative membership must not resolve elsewhere. */
static void namespaces(int self_dir, int init_dir) {
    static const char *const names[] = {"cgroup", "user", "pid"};
    int self_ns = beneath(self_dir, "ns", O_PATH | O_DIRECTORY, 1, PROCFS);
    int init_ns = beneath(init_dir, "ns", O_PATH | O_DIRECTORY, 1, PROCFS);
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        char a[80], b[80];
        ssize_t an = readlinkat(self_ns, names[i], a, sizeof a);
        ssize_t bn = readlinkat(init_ns, names[i], b, sizeof b);
        size_t prefix = strlen(names[i]);
        if (an <= 0 || bn != an || (size_t)an == sizeof a || memcmp(a, b, (size_t)an) != 0 ||
            (size_t)an <= prefix + 3U || memcmp(a, names[i], prefix) != 0 ||
            a[prefix] != ':' || a[prefix + 1U] != '[' || a[an - 1] != ']') fail(IDENTITY);
        for (size_t j = prefix + 2U; j < (size_t)an - 1U; j++) {
            if (a[j] < '0' || a[j] > '9') fail(IDENTITY);
        }
    }
    if (close(self_ns) != 0 || close(init_ns) != 0) fail(PROCFS);
}

static void hierarchy_root(int root) {
    static const char *const absent[] = {"cgroup.kill", "cgroup.type"};
    for (size_t i = 0; i < sizeof absent / sizeof absent[0]; i++) {
        struct open_how how = {
            .flags = O_PATH | O_CLOEXEC | O_NOFOLLOW,
            .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
        };
        int fd = (int)syscall(SYS_openat2, root, absent[i], &how, sizeof how);
        /* Both interfaces exist on non-root cgroups. A real cgroup2 mount
         * alone does not exclude a subtree bind or namespace-root mount. */
        if (fd >= 0) { close(fd); fail(CGROUP2); }
        if (errno != ENOENT) {
            if (errno == ENOSYS || errno == EINVAL || errno == E2BIG || errno == EOPNOTSUPP) fail(OPENAT2);
            fail(CGROUP2);
        }
    }
}

static void domain(int dir, const struct statx *cg) {
    char bytes[32];
    int fd = file_in(dir, "cgroup.type", O_RDONLY, cg, CGROUP2_SUPER_MAGIC, CGROUP_TYPE);
    size_t n = read_small(fd, bytes, sizeof bytes, CGROUP_TYPE);
    if (close(fd) != 0 || !exact_domain(bytes, n)) fail(CGROUP_TYPE);
}

static int own_directory(int root, const char *path, const struct statx *cg) {
    /* Check every fixed ancestor and the leaf: no delegated directory or
     * writable membership interface may give an unprivileged caller migration
     * authority. Metadata only; cgroup.procs/threads are NEVER read or written. */
    char relative[EXACT_PATH_CAP];
    size_t n = strlen(path + 1);
    memcpy(relative, path + 1, n + 1U);
    int leaf = -1;
    for (size_t i = 0; i <= n; i++) {
        if (relative[i] != '/' && relative[i] != '\0') continue;
        char saved = relative[i];
        relative[i] = '\0';
        int dir = beneath(root, relative, O_PATH | O_DIRECTORY, 1, PATH_VALIDATION);
        struct statx st = identity(dir, 1, CGROUP2_SUPER_MAGIC, PATH_VALIDATION);
        if (st.stx_mnt_id != cg->stx_mnt_id || st.stx_dev_major != cg->stx_dev_major ||
            st.stx_dev_minor != cg->stx_dev_minor) fail(PATH_VALIDATION);
        static const char *const names[] = {"cgroup.procs", "cgroup.threads"};
        for (size_t j = 0; j < sizeof names / sizeof names[0]; j++) {
            int fd = file_in(dir, names[j], O_PATH, cg, CGROUP2_SUPER_MAGIC, PATH_VALIDATION);
            if (close(fd) != 0) fail(PATH_VALIDATION);
        }
        domain(dir, cg);
        relative[i] = saved;
        if (saved == '\0') leaf = dir;
        else if (close(dir) != 0) fail(PATH_VALIDATION);
    }
    if (leaf < 0) fail(PATH_VALIDATION);
    return leaf;
}

static void restore_nondumpability(void) {
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
        prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) fail(PRIVILEGE);
}

static void verify_empty_capabilities(void) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0, 0, 0}, {0, 0, 0}};
    if (syscall(SYS_capget, &header, caps) != 0 ||
        caps[0].effective != 0U || caps[0].permitted != 0U || caps[0].inheritable != 0U ||
        caps[1].effective != 0U || caps[1].permitted != 0U ||
        caps[1].inheritable != 0U) fail(FINAL_CREDENTIALS);
    for (unsigned int cap = 0; cap <= 64U; cap++) {
        int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (present < 0) {
            if (errno == EINVAL && cap > CAP_LAST_CAP) break;
            fail(FINAL_CREDENTIALS);
        }
        if (cap == 64U || present != 0 ||
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0) fail(FINAL_CREDENTIALS);
    }
}

static void verify_credentials(uid_t uid, gid_t gid) {
    uid_t ru, eu, su;
    gid_t rg, eg, sg;
    if (uid == 0U || gid == 0U || getresuid(&ru, &eu, &su) != 0 ||
        getresgid(&rg, &eg, &sg) != 0 || ru != uid || eu != uid || su != uid ||
        rg != gid || eg != gid || sg != gid ||
        (uid_t)setfsuid((uid_t)-1) != uid || (gid_t)setfsgid((gid_t)-1) != gid ||
        getgroups(0, NULL) != 0 ||
        prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != (int)LOCKED_SECUREBITS ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) fail(FINAL_CREDENTIALS);
    verify_empty_capabilities();
}

static void reduce_privilege(uid_t uid, gid_t gid) {
    /* All path/namespace setup and the terminal FD open are complete. Retain
     * only SETGID/SETUID/SETPCAP until their final required uses, not broad DAC
     * or ptrace capabilities. No capability can be recovered after capset(0). */
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    const uint32_t transition = (1U << CAP_SETUID) | (1U << CAP_SETGID) | (1U << CAP_SETPCAP);
    struct __user_cap_data_struct caps[2] = {{transition, transition, 0}, {0, 0, 0}};
    if (syscall(SYS_capset, &header, caps) != 0) fail(PRIVILEGE);
    if (setgroups(0, NULL) != 0 || getgroups(0, NULL) != 0 ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) fail(PRIVILEGE);
    unsigned int bits = LOCKED_SECUREBITS;
    if (prctl(PR_SET_SECUREBITS, bits, 0, 0, 0) != 0 ||
        prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != (int)bits) fail(PRIVILEGE);
    for (unsigned int cap = 0; cap <= 64U; cap++) {
        int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (present < 0) {
            if (errno == EINVAL && cap > CAP_LAST_CAP) break;
            fail(PRIVILEGE);
        }
        if (cap == 64U || prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 ||
            prctl(PR_CAPBSET_READ, cap, 0, 0, 0) != 0) fail(PRIVILEGE);
    }
    caps[0].effective = caps[0].permitted = (1U << CAP_SETUID) | (1U << CAP_SETGID);
    if (syscall(SYS_capset, &header, caps) != 0) fail(PRIVILEGE);
    if (setresgid(gid, gid, gid) != 0) fail(CREDENTIAL_TRANSITION);
    restore_nondumpability();
    (void)setfsgid(gid);
    restore_nondumpability();
    if ((gid_t)setfsgid((gid_t)-1) != gid) fail(CREDENTIAL_TRANSITION);
    caps[0].effective = caps[0].permitted = 1U << CAP_SETUID;
    if (syscall(SYS_capset, &header, caps) != 0) fail(PRIVILEGE);
    if (setresuid(uid, uid, uid) != 0) fail(CREDENTIAL_TRANSITION);
    restore_nondumpability();
    (void)setfsuid(uid);
    restore_nondumpability();
    if ((uid_t)setfsuid((uid_t)-1) != uid) fail(CREDENTIAL_TRANSITION);
    /* NO_SETUID_FIXUP intentionally retains the transition capabilities until
     * this explicit clear. Restoring/checking dumpability needs no capability;
     * retained SETUID blocks ordinary capless-peer tracing during UID resets.
     * KEEP_CAPS is OFF and locked; no exec occurs. */
    memset(caps, 0, sizeof caps);
    if (syscall(SYS_capset, &header, caps) != 0) fail(PRIVILEGE);
    verify_empty_capabilities();
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) fail(PRIVILEGE);
    verify_credentials(uid, gid);
}

int main(int argc, char **argv) {
    (void)argv; /* Even argv[0] is ignored. No getenv, stdin, cwd or exec use. */
    if (argc != 1) fail(INVALID_ARGUMENTS);
    uid_t ru, eu, su;
    gid_t rg, eg, sg;
    if (getresuid(&ru, &eu, &su) != 0 || getresgid(&rg, &eg, &sg) != 0 ||
        ru != 0U || eu != 0U || su != 0U || rg != 0U || eg != 0U || sg != 0U) fail(PRIVILEGE);
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) != 0 || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
        syscall(SYS_close_range, 3U, UINT_MAX, 0U) != 0) fail(FD_HYGIENE);
    int root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) fail(PATH_VALIDATION);
    /* Initial fixed-anchor lookup intentionally crosses the proc/sys mounts.
     * All subsequent lookups beneath validated anchors forbid crossings. */
    int proc = beneath(root, "proc", O_PATH | O_DIRECTORY, 0, PROCFS);
    int cg = beneath(root, "sys/fs/cgroup", O_PATH | O_DIRECTORY, 0, CGROUP2);
    struct statx proc_id = identity(proc, 1, PROC_SUPER_MAGIC, PROCFS);
    struct statx cg_id = identity(cg, 1, CGROUP2_SUPER_MAGIC, CGROUP2);
    char pid[32];
    int n = snprintf(pid, sizeof pid, "%ld", (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof pid) fail(PROCFS);
    int self = beneath(proc, pid, O_PATH | O_DIRECTORY, 1, PROCFS);
    int init = beneath(proc, "1", O_PATH | O_DIRECTORY, 1, PROCFS);
    mount_view(self, &proc_id, &cg_id, NULL);
    hierarchy_root(cg);
    namespaces(self, init);
    char path[EXACT_PATH_CAP];
    membership(self, &proc_id, path);
    int dir = own_directory(cg, path, &cg_id);
    struct statx pinned = identity(dir, 1, CGROUP2_SUPER_MAGIC, PATH_VALIDATION);
    const struct drop_anchor drop = pin_drop_anchor(root);
    mount_view(self, &proc_id, &cg_id, &drop.runtime_id);

    /* These namespace reads are the last operations needing broad root setup
     * capabilities (PID1's proc namespace text can require ptrace permission).
     * There is no namespace-changing operation anywhere in this helper. */
    namespaces(self, init);
    int kill_fd = file_in(dir, "cgroup.kill", O_WRONLY, &cg_id, CGROUP2_SUPER_MAGIC, KILL_OPEN);
    struct statx kill_id = identity(kill_fd, 0, CGROUP2_SUPER_MAGIC, KILL_OPEN);
    if ((kill_id.stx_mode & 0200U) == 0U) fail(KILL_OPEN);

    /* Before reduction, resolve the exact leaf once more below the pinned root
     * and compare inode/device/mount identity, not just path strings.
     * Fixed PID1-owned nondelegated placement must prevent external migration;
     * userspace cannot atomically lock membership against a hostile host root. */
    char current[EXACT_PATH_CAP];
    membership(self, &proc_id, current);
    if (strcmp(path, current) != 0) fail(IDENTITY);
    mount_view(self, &proc_id, &cg_id, &drop.runtime_id);
    hierarchy_root(cg);
    int again = own_directory(cg, current, &cg_id);
    struct statx checked = identity(again, 1, CGROUP2_SUPER_MAGIC, IDENTITY);
    if (!exact_same_object(&pinned, &checked)) fail(IDENTITY);
    int checked_kill = file_in(again, "cgroup.kill", O_PATH, &cg_id, CGROUP2_SUPER_MAGIC, KILL_OPEN);
    struct statx checked_kill_id = identity(checked_kill, 0, CGROUP2_SUPER_MAGIC, IDENTITY);
    if (!exact_same_object(&kill_id, &checked_kill_id)) fail(IDENTITY);
    if (close(checked_kill) != 0 || close(again) != 0) fail(IDENTITY);

    /* The selected identities come only from the pinned inode ownership. No
     * contents/NSS/argv/environment lookup, and no new target after the drop. */
    const uid_t uid = (uid_t)drop.file_id.stx_uid;
    const gid_t gid = (gid_t)drop.file_id.stx_gid;
    if ((uint32_t)uid != drop.file_id.stx_uid || (uint32_t)gid != drop.file_id.stx_gid) fail(IDENTITY_ANCHOR);
    recheck_drop_anchor(root, &drop);
    reduce_privilege(uid, gid);

    membership(self, &proc_id, current);
    if (strcmp(path, current) != 0) fail(IDENTITY);
    mount_view(self, &proc_id, &cg_id, &drop.runtime_id);
    hierarchy_root(cg);
    domain(dir, &cg_id);
    static const char *const membership_files[] = {"cgroup.procs", "cgroup.threads"};
    for (size_t i = 0; i < sizeof membership_files / sizeof membership_files[0]; i++) {
        int fd = file_in(dir, membership_files[i], O_PATH, &cg_id, CGROUP2_SUPER_MAGIC, PATH_VALIDATION);
        if (close(fd) != 0) fail(PATH_VALIDATION);
    }
    checked = identity(dir, 1, CGROUP2_SUPER_MAGIC, IDENTITY);
    if (!exact_same_object(&pinned, &checked)) fail(IDENTITY);
    checked_kill_id = identity(kill_fd, 0, CGROUP2_SUPER_MAGIC, IDENTITY);
    if (!exact_same_object(&kill_id, &checked_kill_id)) fail(IDENTITY);
    membership(self, &proc_id, current);
    if (strcmp(path, current) != 0) fail(IDENTITY);
    if (close(drop.file) != 0 || close(drop.parent) != 0 || close(drop.runtime) != 0 ||
        close(dir) != 0 || close(init) != 0 || close(self) != 0 || close(cg) != 0 ||
        close(proc) != 0 || close(root) != 0) fail(FD_HYGIENE);
    verify_credentials(uid, gid);

    /* Exactly one write; no retry, newline, enumeration, or status attestation.
     * Normally the kernel kills this helper before it can return to userspace. */
    if (write(kill_fd, "1", 1U) != 1) fail(KILL_WRITE);
    fail(WRITE_RETURNED);
}
