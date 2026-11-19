//go:build !unix

package secrets

import "os"

// openReadFlags: see open_unix.go. Without O_NONBLOCK, readRegularFile's
// fstat still refuses anything that is not a regular file once it is open.
const openReadFlags = os.O_RDONLY
