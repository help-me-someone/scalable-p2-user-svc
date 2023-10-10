package main

import (
	"log"
	"net/http"
)

// For simplicity, we will just declare a secret here.
// NOTE: For production, please remove this!
var jwtKey = []byte("my_secret_key")

// For simplification let's have a user entry stored in memory.
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

func main() {
	http.HandleFunc("/signin", SignInHanlder)
	http.HandleFunc("/welcome", WelcomeHandler)
	http.HandleFunc("/refresh", RefreshHandler)
	http.HandleFunc("/logout", LogoutHandler)

	// start the server on port 8000
	log.Println("Serving on port 7887")
	log.Fatal(http.ListenAndServe(":7887", nil))
}
