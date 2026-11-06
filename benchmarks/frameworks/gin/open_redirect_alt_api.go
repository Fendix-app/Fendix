package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleOpenRedirectAltAPI(c *gin.Context) {
	next := c.Query("next")
	c.Header("Location", next) // EVAL-SINK
	c.Status(http.StatusFound)
}
