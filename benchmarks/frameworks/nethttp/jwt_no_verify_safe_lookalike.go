package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKeysByID = map[string][]byte{
	"primary":   []byte(os.Getenv("JWT_PRIMARY_KEY")),
	"secondary": []byte(os.Getenv("JWT_SECONDARY_KEY")),
}

func handleJWTNoVerifySafeLookalike(w http.ResponseWriter, r *http.Request) {
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{}) // EVAL-SAFE
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	kid, _ := unverified.Header["kid"].(string)
	key, ok := jwtKeysByID[kid]
	if !ok {
		http.Error(w, "unknown signing key", http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"HS256"}))
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
