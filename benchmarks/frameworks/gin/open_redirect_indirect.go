package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleOpenRedirectIndirect(c *gin.Context) {
	next := c.Query("next")
	redirectTo(c, next)
}

func redirectTo(c *gin.Context, target string) {
	c.Redirect(http.StatusFound, target) // EVAL-SINK
}
