package main

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func handleWeakPasswordHashSafeLookalike(c *gin.Context) {
	data, err := os.ReadFile(filepath.Join(filesDir, "catalog.json"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "catalog unavailable"})
		return
	}
	sum := md5.Sum(data) // EVAL-SAFE
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	c.Header("ETag", etag)
	if c.GetHeader("If-None-Match") == etag {
		c.Status(http.StatusNotModified)
		return
	}
	c.Data(http.StatusOK, "application/json", data)
}
