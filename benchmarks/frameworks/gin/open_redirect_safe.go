package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func handleOpenRedirectSafe(c *gin.Context) {
	next := c.Query("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		next = "/"
	}
	c.Redirect(http.StatusFound, next) // EVAL-SAFE
}
