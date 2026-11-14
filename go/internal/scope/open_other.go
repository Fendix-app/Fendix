//go:build !unix

package scope

import "os"

// OpenRegular opens the regular file at p for reading. This platform has no
// O_NOFOLLOW or O_NONBLOCK, so it checks with Lstat first (a link, a FIFO or a
// device is refused) and then re-checks the opened file.
func OpenRegular(p string) (*os.File, error) {
	pre, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !pre.Mode().IsRegular() {
		return nil, &os.PathError{Op: "open", Path: p, Err: errNotRegular}
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(pre, info) {
		_ = f.Close()
		return nil, &os.PathError{Op: "open", Path: p, Err: errNotRegular}
	}
	return f, nil
}
