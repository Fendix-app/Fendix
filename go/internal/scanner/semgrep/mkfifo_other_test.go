//go:build !unix

package semgrep

import "errors"

func mkfifoForTest(string) error { return errors.New("unsupported") }
