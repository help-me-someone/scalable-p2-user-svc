package main

import (
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func ValidateJWTTOken(r *http.Request) (*Claims, error) {
	// Obtain the session token.
	cookie, err := r.Cookie("token")
	if err != nil {
		return nil, err
	}

	// Get the JWT string from the cookie
	tokenString := cookie.Value

	claims := &Claims{}

	// Parse the JWT and store it inside claims.
	// Will fail in two cases:
	// - Expired
	// - Signature does not match.
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		// We use the same key that was responsible for creating the token.
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("Invalid token.")
	}

	return claims, nil
}
