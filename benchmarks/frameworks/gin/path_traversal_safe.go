package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

func handlePathTraversalSafe(c *gin.Context) {
	name := c.Query("file")
	base, err := filepath.Abs(filesDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server misconfigured"})
		return
	}
	target, err := filepath.Abs(filepath.Join(base, name))
	if err != nil || !strings.HasPrefix(target, base+string(os.PathSeparator)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file"})
		return
	}

	data, err := os.ReadFile(target) // EVAL-SAFE
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}
