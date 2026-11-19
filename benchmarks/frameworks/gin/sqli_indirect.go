package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleSQLiIndirect(c *gin.Context) {
	name := c.Query("name")
	users, err := findUsersByName(name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	c.JSON(http.StatusOK, users)
}

func findUsersByName(name string) ([]user, error) {
	rows, err := db.Query(fmt.Sprintf("SELECT id, name, email FROM users WHERE name = '%s'", name)) // EVAL-SINK
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUsers(rows)
}
