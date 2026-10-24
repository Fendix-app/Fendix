package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func handleJWTNoVerifyIndirect(c *gin.Context) {
	tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	claims, err := claimsFromToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	if claims["role"] != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	subject, _ := claims.GetSubject()
	c.JSON(http.StatusOK, gin.H{"user": subject, "admin": true})
}

func claimsFromToken(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenString, claims); err != nil { // EVAL-SINK
		return nil, err
	}
	return claims, nil
}
