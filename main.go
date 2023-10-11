package main

import (
	"log"
	"net/http"

	"github.com/rs/cors"
)

// For simplicity, we will just declare a secret here.
// NOTE: For production, please remove this!
var jwtKey = []byte("my_secret_key")

// For simplification let's have a user entry stored in memory.
var users = map[string]string{
	"user1@gmail.com": "password1",
	"user2@gmail.com": "password2",
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/signin", SignInHanlder)
	mux.HandleFunc("/welcome", NeedAuth(WelcomeHandler))
	mux.HandleFunc("/refresh", NeedAuth(RefreshHandler))
	mux.HandleFunc("/logout", LogoutHandler)
	mux.HandleFunc("/auth", IsAuthHandler)
	mux.HandleFunc("/", NeedAuth(ForwardHandler))

	// start the server on port 8000
	log.Println("Serving on port 7887")

	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:8000"},
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
		},

		// Enable Debugging for testing, consider disabling in production
		Debug: true,
	}).Handler(mux)

	log.Fatal(http.ListenAndServe(":7887", handler))
}
