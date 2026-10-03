//go:build linux

package exactprocess

import "syscall"

var unixSysProcAttr = syscall.SysProcAttr{Setpgid: true}
