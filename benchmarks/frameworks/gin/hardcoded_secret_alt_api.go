package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

const reportingDSN = "postgres://app:__EVAL_DB_PASSWORD__@db.internal:5432/app?sslmode=require" // EVAL-SINK

func handleHardcodedSecretAltAPI(c *gin.Context) {
	reportingDB, err := sql.Open("postgres", reportingDSN)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database unavailable"})
		return
	}
	defer reportingDB.Close()

	var orders int64
	if err := reportingDB.QueryRowContext(c.Request.Context(), "SELECT count(*) FROM orders").Scan(&orders); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"orders": orders})
}
