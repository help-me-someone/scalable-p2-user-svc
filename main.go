package main

import (
	"log"
	"net/http"
	"os"

	"github.com/rs/cors"
)

// For simplicity, we will just declare a secret here.
// NOTE: For production, please remove this!
// NOTE: This will become an env later.
var jwtKey = []byte("my_secret_key")

// For simplification let's have a user entry stored in memory.
var users = map[string]string{
	"user1@gmail.com": "password1",
	"user2@gmail.com": "password2",
}

var ALLOWED_ORIGIN string

func loadEnvs() {
	ALLOWED_ORIGIN = os.Getenv("ALLOWED_ORIGIN")
}

func main() {

	// Retrieve all environment variables.
	loadEnvs()

	mux := http.NewServeMux()
	mux.HandleFunc("/signin", SignInHanlder)
	mux.HandleFunc("/signup", SignUpHandler)
	mux.HandleFunc("/refresh", RefreshHandler)
	mux.HandleFunc("/logout", LogoutHandler)
	mux.HandleFunc("/", IsAuthHandler)

	// start the server on port 7887
	log.Println("Serving on port 7887")

	handler := cors.New(cors.Options{
		// NOTE(APPY): DON'T FORGET TO REMOVE THIS!
		AllowedOrigins:   []string{ALLOWED_ORIGIN},
		AllowCredentials: true,
		AllowedHeaders: []string{
			"Hx-Current-Url",
			"Hx-Request",
			"Hx-Target",
			"Hx-Boosted",
			"Hx-Current-Url",
			"Hx-Request",
			"Hx-Trigger",
			"Content-Type",
			"X-Custom-Header",
			"*",
		},
		AllowedMethods: []string{
			"POST",
			"GET",
			"PUT",
			"OPTIONS",
			"*",
		},

		// Enable Debugging for testing, consider disabling in production
		Debug: true,
	}).Handler(mux)

	log.Fatal(http.ListenAndServe(":7887", handler))
}
