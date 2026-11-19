package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleOpenRedirectDirect(c *gin.Context) {
	next := c.Query("next")
	c.Redirect(http.StatusFound, next) // EVAL-SINK
}
