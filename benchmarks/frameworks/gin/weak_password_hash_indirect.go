package main

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleWeakPasswordHashIndirect(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	if _, err := db.Exec("INSERT INTO users (username, password_hash) VALUES ($1, $2)", username, hashPassword(password)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "registration failed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"status": "registered"})
}

func hashPassword(password string) string {
	sum := md5.Sum([]byte(password)) // EVAL-SINK
	return hex.EncodeToString(sum[:])
}
