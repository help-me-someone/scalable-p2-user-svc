package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

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

func IsAuthHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := ValidateJWTTOken(r)

	if err != nil {
		resp := map[string]interface{}{
			"authenticated": false,
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := map[string]interface{}{
		"authenticated": true,
		"username":      claims.Username,
	}

	json.NewEncoder(w).Encode(resp)
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := ValidateJWTTOken(r)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		resp := map[string]interface{}{
			"success": false,
			"message": err.Error(),
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Only issue a new token once enough time has elapsed.
	// In our case, we will renew when we're within 30 seconds
	// of expiring.
	if time.Until(claims.ExpiresAt.Time) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		resp := map[string]interface{}{
			"success": false,
			"message": "token not expiring soon",
		}

		json.NewEncoder(w).Encode(resp)
		return
	}

	// Create a new token for the current use, with a renewed expiration time.
	tokenString, expirationTime, err := RenewToken(claims)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		resp := map[string]interface{}{
			"success": false,
			"message": err.Error(),
		}

		json.NewEncoder(w).Encode(resp)
		return
	}

	// Set the new token cookie for the user.
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	resp := map[string]interface{}{
		"success": true,
		"message": "token replaced",
	}

	json.NewEncoder(w).Encode(resp)
}

func SignInHanlder(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "OPTIONS" {

		http.NotFound(w, r)
		return
	}

	var creds Credentials

	creds.Username = r.FormValue("username")
	creds.Password = r.FormValue("password")

	log.Println("User", creds.Username, "attempting to log in...")

	// If we can't get it from the form, then try JSON.
	if len(creds.Password) == 0 || len(creds.Username) == 0 {
		// Decode the request body into credentials.
		// Now we have username and password.
		err := json.NewDecoder(r.Body).Decode(&creds)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			resp := map[string]interface{}{
				"success": false,
				"message": "unable to locate credentials",
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	// Get the expected password
	expectedPassword, ok := users[creds.Username]

	// If the password exists AND it matches we can continue,
	// else we return an "Unauthorized" access.
	if !ok || expectedPassword != creds.Password {
		log.Println("Unvalid login details")
		w.WriteHeader(http.StatusUnauthorized)
		resp := map[string]interface{}{
			"success": false,
			"message": "invalid username/password",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Create a new JWT token using current credentials.
	tokenString, expirationTime, err := CreateJWTToken(&creds)

	if err != nil {
		// Error creating a JWT token, internal server error.
		w.WriteHeader(http.StatusInternalServerError)
		resp := map[string]interface{}{
			"success": false,
			"message": "failed to create token",
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Set client's cookie for "token" as the JWT we generated, we also
	// set the expiry time which is going to be same as the token.
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	resp := map[string]interface{}{
		"success": true,
		"message": "logged in",
		"user":    creds.Username,
		"cookie":  tokenString,
	}

	log.Printf("User logged in: %s\n", creds.Username)

	json.NewEncoder(w).Encode(resp)
}

func WelcomeHandler(w http.ResponseWriter, r *http.Request) {
	// Login successful!
	claims, _ := ValidateJWTTOken(r)
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}

// This is a reverse proxy.
func ForwardHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	log.Println("Handling path:", path)

}
