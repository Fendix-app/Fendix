package main

import (
	"io"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

var allowedFetchHosts = map[string]bool{
	"api.example.com": true,
	"cdn.example.com": true,
}

func handleSSRFSafe(c *gin.Context) {
	target := c.Query("url")
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || !allowedFetchHosts[u.Hostname()] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url not allowed"})
		return
	}

	resp, err := http.Get(u.String()) // EVAL-SAFE
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "fetch failed"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "read failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": resp.StatusCode, "body": string(body)})
}
