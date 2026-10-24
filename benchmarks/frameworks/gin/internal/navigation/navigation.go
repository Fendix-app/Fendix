// Package navigation sends users on to their next page.
package navigation

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RedirectTo(c *gin.Context, target string) {
	c.Redirect(http.StatusFound, target) // EVAL-SINK
}
