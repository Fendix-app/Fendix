package main

import (
	"github.com/gin-gonic/gin"

	"example.com/eval/gin/internal/navigation"
)

func handleOpenRedirectCrossFile(c *gin.Context) {
	next := c.Query("next")
	navigation.RedirectTo(c, next)
}
