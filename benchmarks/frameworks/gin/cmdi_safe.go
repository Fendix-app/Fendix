package main

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func handleCmdiSafe(c *gin.Context) {
	host := c.Query("host")
	out, err := exec.Command("ping", "-c", "1", host).CombinedOutput() // EVAL-SAFE
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ping failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"output": string(out)})
}
