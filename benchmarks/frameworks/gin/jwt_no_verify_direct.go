package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func handleJWTNoVerifyDirect(c *gin.Context) {
	tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{}) // EVAL-SINK
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["role"] != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	subject, _ := claims.GetSubject()
	c.JSON(http.StatusOK, gin.H{"user": subject, "admin": true})
}
