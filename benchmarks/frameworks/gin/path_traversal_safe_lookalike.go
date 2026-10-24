package main

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func handlePathTraversalSafeLookalike(c *gin.Context) {
	data, err := os.ReadFile(filepath.Join(filesDir, "terms-of-service.txt")) // EVAL-SAFE
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}
