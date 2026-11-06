package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const buildDigest = "4b1d6e0f9a7c3e5d2b8f6a1c0e9d7b3a5f2c8e6d4a1b9f7c3e0d5a2b8c6f4e19" // EVAL-SAFE

func handleHardcodedSecretSafeLookalike(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"service": "eval-gin", "buildDigest": buildDigest})
}
