package main

import (
	"github.com/gin-gonic/gin"

	"example.com/eval/gin/internal/greeting"
)

func handleXSSCrossFile(c *gin.Context) {
	name := c.Query("name")
	greeting.Render(c, name)
}
