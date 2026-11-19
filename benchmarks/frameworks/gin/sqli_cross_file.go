package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"example.com/eval/gin/internal/userstore"
)

func handleSQLiCrossFile(c *gin.Context) {
	name := c.Query("name")
	users, err := userstore.FindByName(db, name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	c.JSON(http.StatusOK, users)
}
