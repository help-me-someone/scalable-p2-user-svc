package main

import (
	"encoding/json"
	"net/http"
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

	// Create a new JWT token using current credentials.
	tokenString, expirationTime, err := CreateJWTToken(&creds)

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
