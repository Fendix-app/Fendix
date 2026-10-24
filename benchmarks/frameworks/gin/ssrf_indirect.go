package main

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleSSRFIndirect(c *gin.Context) {
	target := c.Query("url")
	status, body, err := fetchRemote(target)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "fetch failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": status, "body": body})
}

func fetchRemote(target string) (int, string, error) {
	resp, err := http.Get(target) // EVAL-SINK
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(body), nil
}
