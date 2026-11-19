//go:build !linux

package semgrep

import "os"

// killTree kills p. Without /proc the descendants cannot be listed here; the
// hosted engine runs on Linux, where killtree_linux.go takes the tree down.
func killTree(p *os.Process) error { return p.Kill() }
