package main

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func handleCmdiIndirect(c *gin.Context) {
	host := c.Query("host")
	out, err := runPing(host)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ping failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"output": string(out)})
}

func runPing(host string) ([]byte, error) {
	return exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput() // EVAL-SINK
}
