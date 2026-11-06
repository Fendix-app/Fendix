package main

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func handleCmdiAltAPI(c *gin.Context) {
	host := c.Query("host")
	out, err := exec.CommandContext(c.Request.Context(), "sh", "-c", "ping -c 1 "+host).Output() // EVAL-SINK
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ping failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"output": string(out)})
}
