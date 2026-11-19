package main

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func handlePathTraversalDirect(c *gin.Context) {
	name := c.Query("file")
	data, err := os.ReadFile(filepath.Join(filesDir, name)) // EVAL-SINK
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}
