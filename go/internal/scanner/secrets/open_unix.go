//go:build unix

package secrets

import (
	"os"
	"syscall"
)

// openReadFlags opens a scanned file without blocking: if a FIFO is swapped in
// for a regular file after the walk saw it, the open returns instead of
// waiting for a writer, and readRegularFile's fstat then refuses it.
const openReadFlags = os.O_RDONLY | syscall.O_NONBLOCK
