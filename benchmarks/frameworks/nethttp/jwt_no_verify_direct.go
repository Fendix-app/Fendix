package main

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func handleJWTNoVerifyDirect(w http.ResponseWriter, r *http.Request) {
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{}) // EVAL-SINK
	if err != nil {
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
