/* Fixed Linux/x86_64 profile. FDs: 3=self, 4=bwrap, 5=runtime, 6=policy, 7=trusted setup report.
 * No command, environment, mount, network, or argv configuration is accepted.
 * Test builds change only identity admission, never the containment profile. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
static void __attribute__((noreturn)) fail(void) { _exit(125); }
int main(int argc,char **argv) {
#if !defined(__x86_64__)
 (void)argc;(void)argv;fail();
#else
 if (argc!=1 && !(argc==2 && !strcmp(argv[1],"--preflight"))) fail();
 if (getuid()==0 || geteuid()!=getuid() || getegid()!=getgid()) fail();
#ifndef RECONDUCTOR_TEST_IDENTITY
 gid_t groups[64];int n=getgroups(64,groups);if(n<0)fail();
 for(int i=0;i<n;i++)if(groups[i]!=getgid())fail();
#endif
 pid_t parent=getppid();
 if(parent==1 || prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()!=parent)fail();
 if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1)fail();
 if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0))fail();
 struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
 struct __user_cap_data_struct c[2]={{0,0,0},{0,0,0}};
 if(syscall(SYS_capset,&h,c))fail();
 struct rlimit core={0,0};if(setrlimit(RLIMIT_CORE,&core))fail();
 /* Keep only the deliberate object FDs until bwrap consumes them. */
 if(syscall(SYS_close_range,8U,UINT_MAX,0U) || close(3))fail();
 if(fcntl(4,F_SETFD,FD_CLOEXEC))fail();
 char *const env[]={NULL};
 char *const args[]={
  "/usr/bin/bwrap",
  "--unshare-user","--unshare-pid","--unshare-ipc","--unshare-uts","--unshare-net",
  "--disable-userns","--assert-userns-disabled","--uid","0","--gid","0",
  "--hostname","exact-offline","--clearenv","--cap-drop","ALL",
  "--new-session","--die-with-parent","--info-fd","7",
  "--dir","/runtime","--ro-bind-fd","5","/runtime/exact-runtime",
  "--remount-ro","/","--chdir","/","--seccomp","6",
  "--","/runtime/exact-runtime",argc==2?"--preflight":NULL,NULL
 };
 syscall(SYS_execveat,4,"",args,env,AT_EMPTY_PATH);
 fail();
#endif
}
