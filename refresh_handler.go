package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func RefreshHandler(w http.ResponseWriter, r *http.Request) {

	claims, err := ValidateJWTTOken(r)
	if err != nil {
		switch err {
		case http.ErrNoCookie:
			w.WriteHeader(http.StatusUnauthorized)
		case jwt.ErrSignatureInvalid:
			w.WriteHeader(http.StatusUnauthorized)
		case fmt.Errorf("Invalid token."): // This is kind of evil...
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
		return
	}

	// Only issue a new token once enough time has elapsed.
	// In our case, we will renew when we're within 30 seconds
	// of expiring.
	if time.Until(claims.ExpiresAt.Time) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Create a new token for the current use, with a renewed expiration time.
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set the new token cookie for the user.
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}
