package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleWeakRandomTokenSafe(c *gin.Context) {
	email := c.PostForm("email")
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil { // EVAL-SAFE
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reset failed"})
		return
	}
	token := hex.EncodeToString(b)
	if _, err := db.Exec("INSERT INTO password_resets (email, token) VALUES ($1, $2)", email, token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reset failed"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"status": "reset email queued"})
}
