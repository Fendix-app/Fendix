//go:build linux

package semgrep

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// killTree kills p and every process descended from it. Nothing is killed
// until the whole tree is frozen: p is stopped first, then every descendant
// found is stopped, and the scan repeats until it finds no new one (a child
// started between two reads is stopped by the next). Only then is everything
// killed, descendants first and p last. A frozen wrapper cannot notice that its
// worker died, print a document and exit 0 while the rest of the tree is still
// being found (round 5, DE6-02), so a run killed at its deadline never reads as
// one that finished. The descendants are read from /proc before anything is
// killed, because a killed parent's children are reparented and can no longer
// be found by their parent.
func killTree(p *os.Process) error {
	_ = syscall.Kill(p.Pid, syscall.SIGSTOP)
	pids := map[int]bool{}
	for round := 0; round < 4; round++ {
		fresh := 0
		for _, pid := range descendantsOf(p.Pid) {
			if !pids[pid] {
				pids[pid] = true
				fresh++
				_ = syscall.Kill(pid, syscall.SIGSTOP)
			}
		}
		if fresh == 0 {
			break
		}
	}
	for pid := range pids {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	return p.Kill()
}

// descendantsOf lists the processes whose ancestry, by parent pid in
// /proc/<pid>/stat, leads to root.
func descendantsOf(root int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	parent := map[int]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// pid (comm) state ppid ...: comm can hold spaces and parentheses, so
		// the fields start after the last ')'.
		s := string(data)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 {
			continue
		}
		if ppid, err := strconv.Atoi(f[1]); err == nil {
			parent[pid] = ppid
		}
	}
	var out []int
	for pid := range parent {
		for cur, hops := pid, 0; hops < 64; hops++ {
			pp, ok := parent[cur]
			if !ok || pp <= 1 {
				break
			}
			if pp == root {
				out = append(out, pid)
				break
			}
			cur = pp
		}
	}
	return out
}
