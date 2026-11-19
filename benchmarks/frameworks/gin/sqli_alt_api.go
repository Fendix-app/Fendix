package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleSQLiAltAPI(c *gin.Context) {
	name := c.Query("name")
	var u user
	err := db.QueryRow(fmt.Sprintf("SELECT id, name, email FROM users WHERE name = '%s'", name)).Scan(&u.ID, &u.Name, &u.Email) // EVAL-SINK
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	c.JSON(http.StatusOK, u)
}
