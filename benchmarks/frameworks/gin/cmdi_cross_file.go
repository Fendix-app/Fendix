package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"example.com/eval/gin/internal/netdiag"
)

func handleCmdiCrossFile(c *gin.Context) {
	host := c.Query("host")
	out, err := netdiag.Ping(host)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ping failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"output": string(out)})
}
