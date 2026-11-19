package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var jwtKeysByID = map[string][]byte{
	"primary":   []byte(os.Getenv("JWT_PRIMARY_KEY")),
	"secondary": []byte(os.Getenv("JWT_SECONDARY_KEY")),
}

func handleJWTNoVerifySafeLookalike(c *gin.Context) {
	tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{}) // EVAL-SAFE
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	kid, _ := unverified.Header["kid"].(string)
	key, ok := jwtKeysByID[kid]
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unknown signing key"})
		return
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"HS256"}))
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
