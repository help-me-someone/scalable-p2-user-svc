// TODO: Change X-Custom-Header, what kind of horrible naming is this.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/help-me-someone/scalable-p2-db/models/user"
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

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	// Set username in the response header
	// so we can forward it to the request.
	w.Header().Add("X-Username", claims.Username)

	resp := map[string]interface{}{
		"authenticated": true,
		"username":      claims.Username,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func CustomHeaderCookieAuth(w http.ResponseWriter, r *http.Request) {
	cookie := r.Header.Get("X-Custom-Header")
	if len(cookie) > 6 {
		cookie = cookie[6:]
		CheckAuth(w, cookie)
		return
	}
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
		Domain:   "http://tiktok.localhost",
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
	resp, err := http.Get(fmt.Sprintf("http://db-svc:8083/user/%s", creds.Username))
	if err != nil {
		log.Println(err)
		FailResponse(w, http.StatusInternalServerError, fmt.Sprintf("Get user request failed. %s", err))
		return
	}
	defer resp.Body.Close()

	getResponse := struct {
		Success bool      `json:"success"`
		Message string    `json:"message"`
		User    user.User `json:"user"`
	}{}

	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	if err != nil {
		FailResponse(w, http.StatusBadRequest, "Could not get user information.")
		return
	}

	hashedPassword := getResponse.User.HashedPassword

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
		Domain:   "http://tiktok.localhost",
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

	// Get the database connection which should have
	// been added by the database middleware.
	resp, err := http.Get(fmt.Sprintf("http://db-svc:8083/user/%s", username))
	if err != nil {
		log.Println(err)
		FailResponse(w, http.StatusInternalServerError, fmt.Sprintf("Get user request failed. %s", err))
		return
	}
	defer resp.Body.Close()

	// Check if the user alreay exists within the database.
	// A little unorthodox but we can check by seeing whether we
	// get the expected error or not. We expect RecordNotFound.

	getResponse := struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{}
	if err = json.NewDecoder(resp.Body).Decode(&getResponse); err != nil {
		FailResponse(w, http.StatusBadRequest, "Failed to decode reponse from get user.")
		return
	}

	if getResponse.Message != "User not found." {
		// This means that the user already exists.
		FailResponse(w, http.StatusBadRequest, "User already exists.")
		return
	}

	// If reach this line it means that we are now ready to make a new
	// record for the user.

	// Prepare the password.
	password, err = HashPassword(password)
	if err != nil {
		log.Println(err)
		FailResponse(w, http.StatusBadRequest, "Failed to hash password.")
		return
	}

	// Create the new entry.
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(map[string]interface{}{
		"username":        username,
		"hashed_password": password,
	})

	// Ask the database service to create the user.
	resp, err = http.Post("http://db-svc:8083/user", "application/json", &buf)
	if err != nil {
		log.Println(err)
		FailResponse(w, http.StatusInternalServerError, "Create user request failed.")
		return
	}
	defer resp.Body.Close()

	// Check the creation response.
	createResp := struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{}

	err = json.NewDecoder(resp.Body).Decode(&createResp)
	if err != nil {
		log.Println(err)
		FailResponse(w, http.StatusInternalServerError, "Failed to decode creation response.")
		return
	}

	if createResp.Success {
		log.Println("Successfully created user", username)
		response.Encode(map[string]interface{}{
			"success": true,
			"message": "User successfully created.",
		})
		return
	} else {
		log.Println(createResp.Message)
		FailResponse(w, http.StatusInternalServerError, "Failed to create user.")
	}
}

func WelcomeHandler(w http.ResponseWriter, r *http.Request) {
	// Login successful!
	claims, _ := ValidateJWTTOken(r)
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}
