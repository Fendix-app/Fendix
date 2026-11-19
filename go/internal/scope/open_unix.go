//go:build unix

package scope

import (
	"os"
	"syscall"
)

// OpenRegular opens the regular file at p for reading without ever blocking on
// it and without following a link at its last element: O_NONBLOCK keeps an open
// of a FIFO, a device or a socket from waiting for a peer, and O_NOFOLLOW makes
// an open of a symbolic link fail instead of reading what it points at (which
// could be outside the scan root). A file that is not a regular file once
// opened is refused. The caller closes it.
func OpenRegular(p string) (*os.File, error) {
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, &os.PathError{Op: "open", Path: p, Err: errNotRegular}
	}
	return f, nil
}
