package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"example.com/eval/gin/internal/docstore"
)

func handlePathTraversalCrossFile(c *gin.Context) {
	name := c.Query("file")
	data, err := docstore.Read(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}
