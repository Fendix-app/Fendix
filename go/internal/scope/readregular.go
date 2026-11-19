package scope

import (
	"errors"
	"fmt"
	"io"
)

// ReadRegular reads the regular file at p, at most max bytes, without blocking on
// a named pipe or device and without following a link at its last element
// (OpenRegular). A file longer than max is an error, never a short read. It is
// the one way an analyzer reads a path from the scan tree after the walk named
// it (contract C6): a name can be swapped for a pipe between listing and
// reading.
func ReadRegular(p string, max int64) ([]byte, error) {
	f, err := OpenRegular(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("read %s: %w", p, ErrTooLarge)
	}
	return data, nil
}

// ErrTooLarge is why ReadRegular refuses a file over its limit.
var ErrTooLarge = errors.New("file larger than the read limit")
