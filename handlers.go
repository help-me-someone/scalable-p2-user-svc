package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Content-Type", "text/html; charset=utf-8")
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	// Clear the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	claims, _ := ValidateJWTTOken(r)
	// Only issue a new token once enough time has elapsed.
	// In our case, we will renew when we're within 30 seconds
	// of expiring.
	if time.Until(claims.ExpiresAt.Time) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Create a new token for the current use, with a renewed expiration time.
	tokenString, expirationTime, err := RenewToken(claims)
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

func SignInHanlder(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "OPTIONS" {

		http.NotFound(w, r)
		return
	}
	enableCors(&w)

	var creds Credentials

	creds.Username = r.FormValue("username")
	creds.Password = r.FormValue("password")

	// If we can't get it from the form, then try JSON.
	if len(creds.Password) == 0 || len(creds.Username) == 0 {
		// Decode the request body into credentials.
		// Now we have username and password.
		err := json.NewDecoder(r.Body).Decode(&creds)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
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

func WelcomeHandler(w http.ResponseWriter, r *http.Request) {
	// Login successful!
	claims, _ := ValidateJWTTOken(r)
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}

// This is a reverse proxy.
func ForwardHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	target, err := Target(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	targetUrl, err := url.Parse(target)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	Proxy(targetUrl).ServeHTTP(w, r)

}
