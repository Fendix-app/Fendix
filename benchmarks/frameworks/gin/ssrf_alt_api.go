package main

import (
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

var previewClient = &http.Client{Timeout: 10 * time.Second}

func handleSSRFAltAPI(c *gin.Context) {
	target := c.Query("url")
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, target, nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid url"})
		return
	}
	resp, err := previewClient.Do(req) // EVAL-SINK
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
