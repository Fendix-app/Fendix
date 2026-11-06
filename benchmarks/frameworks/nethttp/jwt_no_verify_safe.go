package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSigningKey = []byte(os.Getenv("JWT_SIGNING_KEY"))

func handleJWTNoVerifySafe(w http.ResponseWriter, r *http.Request) {
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) { return jwtSigningKey, nil }, jwt.WithValidMethods([]string{"HS256"})) // EVAL-SAFE
	if err != nil || !token.Valid {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["role"] != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	subject, _ := claims.GetSubject()
	writeJSON(w, map[string]any{"user": subject, "admin": true})
}
