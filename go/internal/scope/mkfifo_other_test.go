//go:build !unix

package scope

import "errors"

func mkfifo(string) error { return errors.New("unsupported") }
