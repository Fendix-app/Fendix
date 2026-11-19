package main

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func handleJWTNoVerifyIndirect(w http.ResponseWriter, r *http.Request) {
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims, err := claimsFromToken(tokenString)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if claims["role"] != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	subject, _ := claims.GetSubject()
	writeJSON(w, map[string]any{"user": subject, "admin": true})
}

func claimsFromToken(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenString, claims); err != nil { // EVAL-SINK
		return nil, err
	}
	return claims, nil
}
