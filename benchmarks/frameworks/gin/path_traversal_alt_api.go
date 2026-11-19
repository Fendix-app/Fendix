package main

import (
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func handlePathTraversalAltAPI(c *gin.Context) {
	name := c.Query("file")
	c.File(filepath.Join(filesDir, name)) // EVAL-SINK
}
