package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

const activeUsersTable = "users"

func handleSQLiSafeLookalike(c *gin.Context) {
	rows, err := db.Query(fmt.Sprintf("SELECT id, name, email FROM %s WHERE active = true ORDER BY name", activeUsersTable)) // EVAL-SAFE
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
