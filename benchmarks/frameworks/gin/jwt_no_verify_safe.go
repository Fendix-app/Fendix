package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var jwtSigningKey = []byte(os.Getenv("JWT_SIGNING_KEY"))

func handleJWTNoVerifySafe(c *gin.Context) {
	tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) { return jwtSigningKey, nil }, jwt.WithValidMethods([]string{"HS256"})) // EVAL-SAFE
	if err != nil || !token.Valid {
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
