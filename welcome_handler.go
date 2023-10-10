package main

import (
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func WelcomeHandler(w http.ResponseWriter, r *http.Request) {

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

	// Login successful!
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}
