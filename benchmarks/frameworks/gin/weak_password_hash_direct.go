package main

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleWeakPasswordHashDirect(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	sum := md5.Sum([]byte(password)) // EVAL-SINK
	if _, err := db.Exec("INSERT INTO users (username, password_hash) VALUES ($1, $2)", username, hex.EncodeToString(sum[:])); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "registration failed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"status": "registered"})
}
