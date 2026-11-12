//go:build linux

package semgrep

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// killTree kills p and every process descended from it. The descendants are
// read from /proc before anything is killed (a killed parent's children are
// reparented and can no longer be found by their parent), and the list is
// taken twice so a child started between the first read and the kill is not
// missed.
func killTree(p *os.Process) error {
	pids := map[int]bool{}
	for round := 0; round < 2; round++ {
		for _, pid := range descendantsOf(p.Pid) {
			pids[pid] = true
		}
		for pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
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
