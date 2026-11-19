package main

import (
	"fmt"
	"math/rand"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleWeakRandomTokenDirect(c *gin.Context) {
	email := c.PostForm("email")
	token := fmt.Sprintf("%016x%016x", rand.Uint64(), rand.Uint64()) // EVAL-SINK
	if _, err := db.Exec("INSERT INTO password_resets (email, token) VALUES ($1, $2)", email, token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reset failed"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"status": "reset email queued"})
}
