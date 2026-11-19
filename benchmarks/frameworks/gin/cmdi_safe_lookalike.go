package main

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

const dataVolume = "/var/lib/app"

func handleCmdiSafeLookalike(c *gin.Context) {
	out, err := exec.Command("sh", "-c", "df -h "+dataVolume).CombinedOutput() // EVAL-SAFE
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "df failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"output": string(out)})
}
