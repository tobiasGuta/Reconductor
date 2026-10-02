/* Trusted Linux launch boundary. No runtime path or argv is accepted from
 * stdin, environment, or caller arguments. The default build can ONLY run two
 * harmless preflight operations. Offline execution is compiled ONLY in tests.
 * This is not a production exact-action launcher or sandbox. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static void __attribute__((noreturn)) fail(void) { _exit(125); }

#ifndef RECONDUCTOR_TEST_RUNTIME
static void __attribute__((noreturn)) bwrap(char *const args[], char *const env[]) {
    int fd = open("/usr/bin/bwrap", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat st;
    char magic[4];
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        !(st.st_mode & 0111) || (st.st_mode & 06022)) fail();
    if (read(fd, magic, sizeof magic) != (ssize_t)sizeof magic || memcmp(magic, "\177ELF", sizeof magic)) fail();
    fexecve(fd, args, env);
    fail();
}
#endif

int main(int argc, char **argv) {
    pid_t parent = getppid();
    if (parent == 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) fail();
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) fail();
    /* Drop even passive inheritable bits; no host privilege reaches exec. */
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0, 0, 0}, {0, 0, 0}};
    if (syscall(SYS_capset, &header, caps)) fail();
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core)) fail();
#ifdef RECONDUCTOR_TEST_DESCENDANT
    /* FD 4 is a test-only PID report. FD 3 is the pinned launcher inode. */
    if (syscall(SYS_close_range, 5U, UINT_MAX, 0U) || close(3)) fail();
    pid_t child = fork();
    if (child < 0) fail();
    if (child == 0) {
        close(4);
        for (;;) pause(); /* Stays in the parent's process group. */
    }
    if (dprintf(4, "%ld\n", (long)child) < 0 || close(4)) fail();
#else
    /* Fail closed if explicit child-side hygiene is unavailable. */
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U)) fail();
#endif
    char *const clean_env[] = {NULL};
#ifdef RECONDUCTOR_TEST_RUNTIME
    (void)argv;
    if (argc != 1) fail();
    char *const args[] = {RECONDUCTOR_TEST_RUNTIME, RECONDUCTOR_TEST_BEHAVIOR, NULL};
    execve(RECONDUCTOR_TEST_RUNTIME, args, clean_env);
#else
    /* A privileged caller is not proof of unprivileged host capability. */
    if (getuid() == 0 || geteuid() == 0) fail();
    if (argc != 2) fail();
    if (!strcmp(argv[1], "--help")) {
        char *const args[] = {"/usr/bin/bwrap", "--help", NULL};
        bwrap(args, clean_env);
    } else if (!strcmp(argv[1], "--namespace-probe")) {
#if !defined(__x86_64__)
        /* This minimal root is deliberately Fedora x86_64-specific. */
        fail();
#else
        char *const args[] = {
            "/usr/bin/bwrap", "--unshare-user", "--unshare-pid", "--unshare-net",
            "--unshare-ipc", "--unshare-uts", "--disable-userns",
            "--assert-userns-disabled", "--clearenv", "--cap-drop", "ALL",
            "--new-session", "--die-with-parent",
            "--dir", "/usr", "--dir", "/usr/bin", "--dir", "/lib64",
            "--ro-bind", "/usr/bin/true", "/usr/bin/true",
            "--ro-bind", "/usr/lib64/libc.so.6", "/lib64/libc.so.6",
            "--ro-bind", "/usr/lib64/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2",
            "--chdir", "/", "--", "/usr/bin/true", NULL
        };
        bwrap(args, clean_env);
#endif
    }
#endif
    fail();
}
