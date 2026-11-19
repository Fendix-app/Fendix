//go:build unix

package semgrep

import "syscall"

func mkfifoForTest(p string) error { return syscall.Mkfifo(p, 0o644) }
