package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleSQLiDirect(c *gin.Context) {
	name := c.Query("name")
	rows, err := db.Query(fmt.Sprintf("SELECT id, name, email FROM users WHERE name = '%s'", name)) // EVAL-SINK
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
