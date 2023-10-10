package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func SignInHanlder(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	// Decode the request body into credentials.
	// Now we have username and password.
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the expected password
	expectedPassword, ok := users[creds.Username]

	// If the password exists AND it matches we can continue,
	// else we return an "Unauthorized" access.
	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Declare the expiration time of the token. (5 minutes)
	expirationTime := time.Now().Add(5 * time.Minute)

	// Create he JWT claim which includes the username and expiry time.
	claims := &Claims{
		Username: creds.Username, RegisteredClaims: jwt.RegisteredClaims{
			// Expressed as unix miliseconds (JWL specification)
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Declare the token with the algorithm used for signing.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// Error creating a JWT token, internal server error.
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set client's cookie for "token" as the JWT we generated, we also
	// set the expiry time which is going to be same as the token.
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}
