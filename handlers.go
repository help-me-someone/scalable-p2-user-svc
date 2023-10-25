// TODO: Change X-Custom-Header, what kind of horrible naming is this.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/help-me-someone/scalable-p2-db/functions/crud"
)

func FailResponse(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"message": message,
	})
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

func CheckAuth(w http.ResponseWriter, cookie string) {
	claims, err := ValidateRawJTWToken(cookie)

	if err != nil {
		resp := map[string]interface{}{
			"authenticated": false,
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Set username in the response header
	// so we can forward it to the request.
	w.Header().Add("X-Username", claims.Username)

	resp := map[string]interface{}{
		"authenticated": true,
		"username":      claims.Username,
	}

	log.Println("Ok.")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func CustomHeaderCookieAuth(w http.ResponseWriter, r *http.Request) {
	cookie := r.Header.Get("X-Custom-Header")
	if len(cookie) > 6 {
		cookie = cookie[6:]
		CheckAuth(w, cookie)
		log.Println("Okay found cookie.")
		return
	}
	log.Println("Wait where the cookie at?")

	resp := map[string]interface{}{
		"authenticated": false,
	}
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(resp)
	return
}

// There are two different ways a cookie can be passed.
// It's either via token or via "X-Custom-Header"
func IsAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		log.Println("Handling options")
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Println("Caught by auth:", r.URL.String())
	if cookie, err := r.Cookie("token"); err == nil {
		CheckAuth(w, cookie.Value)
	} else {
		CustomHeaderCookieAuth(w, r)
	}
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := ValidateJWTTOken(r)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	// Only issue a new token once enough time has elapsed.
	// In our case, we will renew when we're within 30 seconds
	// of expiring.
	if time.Until(claims.ExpiresAt.Time) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Token not expiring soon.",
		})
		return
	}

	// Create a new token for the current use, with a renewed expiration time.
	tokenString, expirationTime, err := RenewToken(claims)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	// Set the new token cookie for the user.
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		Domain:   "toktik.localhost",
		Path:     "/",
	})

	resp := map[string]interface{}{
		"success": true,
		"message": "token replaced",
	}

	json.NewEncoder(w).Encode(resp)
}

func SignInHanlder(w http.ResponseWriter, r *http.Request) {
	response := json.NewEncoder(w)

	// Make sure the request is valid.
	if r.Method != "POST" && r.Method != "OPTIONS" {
		FailResponse(w, http.StatusNotFound, "Invalid method.")
		return
	}

	// Retrieve the credentials.
	var creds Credentials
	creds.Username = r.FormValue("username")
	creds.Password = r.FormValue("password")

	// If we can't get it from the form, then try JSON.
	if len(creds.Password) == 0 || len(creds.Username) == 0 {
		// Decode the request body into credentials.
		err := json.NewDecoder(r.Body).Decode(&creds)
		if err != nil {
			FailResponse(w, http.StatusBadRequest, "Unable to locate credentials.")
			return
		}
	}

	if len(creds.Password) == 0 || len(creds.Username) == 0 {
		FailResponse(w, http.StatusUnauthorized, "Invalid username/password.")
		return
	}

	// Make the username case insensitive.
	creds.Username = strings.ToLower(creds.Username)

	// Get the user info.
	connection, _ := GetDatabaseConnection(DB_USERNAME, DB_PASSWORD, DB_IP)
	usr, err := crud.GetUserByName(connection, creds.Username)
	if err != nil {
		log.Println(err)
		FailResponse(w, http.StatusInternalServerError, "Invalid username/password.")
		return
	}

	hashedPassword := usr.HashedPassword

	// If the password exists AND it matches we can continue,
	// else we return an "Unauthorized" access.
	if !CheckPasswordHash(creds.Password, hashedPassword) {
		FailResponse(w, http.StatusUnauthorized, "Invalid username/password.")
		return
	}

	// Create a new JWT token using current credentials.
	tokenString, expirationTime, err := CreateJWTToken(&creds)

	if err != nil {
		// Error creating a JWT token, internal server error.
		FailResponse(w, http.StatusInternalServerError, "Failed to create token.")
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
		Domain:   "toktik.localhost",
		Path:     "/",
	})

	successResponse := map[string]interface{}{
		"success": true,
		"message": "logged in",
		"user":    creds.Username,
		"cookie":  tokenString,
	}

	response.Encode(successResponse)
}

// RegisterHanlder deals with the registration of a user.
func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	response := json.NewEncoder(w)

	// Make sure the method is POST.
	if r.Method != "POST" {
		FailResponse(w, http.StatusMethodNotAllowed, "Invalid method.")
		return
	}

	re := RegistrationEntry{}
	if err := json.NewDecoder(r.Body).Decode(&re); err != nil {
		FailResponse(w, http.StatusBadRequest, "Failed to decode entry.")
		return
	}

	// Retrieve the values from the forms.
	username := re.Username
	password := re.Password
	confirmPassword := re.ConfirmPassword

	usernameEmpty := len(username) == 0
	passwordEmpty := len(password) == 0
	confirmPasswordEmpty := len(confirmPassword) == 0

	// Make sure the username and password is provided.
	if usernameEmpty || passwordEmpty || confirmPasswordEmpty {
		FailResponse(w, http.StatusBadRequest, "Username/password mising.")
		return
	}

	// Make sure the password and confirmPassword matches.
	if password != confirmPassword {
		FailResponse(w, http.StatusBadRequest, "Password does not match.")
		return
	}

	// Make the username name case insensitive.
	username = strings.ToLower(username)

	connection, _ := GetDatabaseConnection(DB_USERNAME, DB_PASSWORD, DB_IP)

	// Make sure the user doesn't already exists.
	_, err := crud.GetUserByName(connection, username)
	if err != nil && err.Error() != "record not found" {
		FailResponse(w, http.StatusInternalServerError, "Something went wrong.")
		return
	}

	// Check if the user alreay exists within the database.
	// A little unorthodox but we can check by seeing whether we
	// get the expected error or not. We expect RecordNotFound.

	// Prepare the password.
	password, err = HashPassword(password)
	if err != nil {
		log.Println(err)
		FailResponse(w, http.StatusBadRequest, "Failed to hash password.")
		return
	}

	// Create the user.
	_, err = crud.CreateUser(connection, username, password)
	if err != nil {
		log.Println(err)
		FailResponse(w, http.StatusInternalServerError, "Failed to create user.")
		return
	}

	log.Println("Successfully created user", username)
	response.Encode(map[string]interface{}{
		"success": true,
		"message": "User successfully created.",
	})
}

func WelcomeHandler(w http.ResponseWriter, r *http.Request) {
	// Login successful!
	claims, _ := ValidateJWTTOken(r)
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}
