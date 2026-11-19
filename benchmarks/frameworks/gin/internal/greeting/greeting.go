// Package greeting renders the welcome page.
package greeting

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Render(c *gin.Context, name string) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fmt.Sprintf("<html><body><h1>Hello, %s</h1></body></html>", name))) // EVAL-SINK
}
