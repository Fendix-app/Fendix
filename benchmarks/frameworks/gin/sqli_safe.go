package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleSQLiSafe(c *gin.Context) {
	name := c.Query("name")
	rows, err := db.Query("SELECT id, name, email FROM users WHERE name = $1", name) // EVAL-SAFE
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	users, err := scanUsers(rows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	c.JSON(http.StatusOK, users)
}
