package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const dashboardPath = "/account/dashboard"

func handleOpenRedirectSafeLookalike(c *gin.Context) {
	c.Redirect(http.StatusFound, dashboardPath) // EVAL-SAFE
}
