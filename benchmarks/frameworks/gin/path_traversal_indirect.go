package main

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func handlePathTraversalIndirect(c *gin.Context) {
	name := c.Query("file")
	data, err := readStoredFile(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}

func readStoredFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(filesDir, name)) // EVAL-SINK
}
