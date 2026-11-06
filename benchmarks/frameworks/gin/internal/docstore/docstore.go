// Package docstore reads stored customer documents.
package docstore

import (
	"os"
	"path/filepath"
)

const baseDir = "/srv/app/files"

func Read(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(baseDir, name)) // EVAL-SINK
}
