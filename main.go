package main

import (
	"log"
	"net/http"
	"os"

	db "github.com/help-me-someone/scalable-p2-db"
	"github.com/help-me-someone/scalable-p2-db/models/user"
	"github.com/help-me-someone/scalable-p2-db/models/video"
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

var (
	ALLOWED_ORIGIN string
	DB_USERNAME    string
	DB_PASSWORD    string
	DB_IP          string
)

func loadEnvs() {
	ALLOWED_ORIGIN = os.Getenv("ALLOWED_ORIGIN")
	DB_USERNAME = os.Getenv("DB_USERNAME")
	DB_PASSWORD = os.Getenv("DB_PASSWORD")
	DB_IP = os.Getenv("DB_IP")
}

func main() {
	// Retrieve all environment variables.
	loadEnvs()

	// Initalize the database.
	toktik_db, _ := GetDatabaseConnection(DB_USERNAME, DB_PASSWORD, DB_IP)
	if !toktik_db.Migrator().HasTable(&user.User{}) && !toktik_db.Migrator().HasTable(&video.Video{}) {
		db.InitTables(toktik_db)
		log.Println("Database initialized!")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/signin", SignInHanlder)
	mux.HandleFunc("/signup", SignUpHandler)
	mux.HandleFunc("/refresh", RefreshHandler)
	mux.HandleFunc("/logout", LogoutHandler)
	mux.HandleFunc("/", IsAuthHandler)

	// start the server on port 7887
	log.Println("Serving on port 7887")
	log.Printf("Allowed origin: %s", ALLOWED_ORIGIN)

	handler := cors.New(cors.Options{
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
