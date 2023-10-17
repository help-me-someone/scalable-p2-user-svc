package main

import (
	"log"
	"net/http"

	db "github.com/help-me-someone/scalable-p2-db"
	"github.com/help-me-someone/scalable-p2-db/models/user"
	"github.com/rs/cors"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
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

func main() {
	// TODO: Load this via environments.
	dsn := "user:password@tcp(mysql:3306)/toktik-db?charset=utf8mb4&parseTime=True&loc=Local"

	toktik_db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Panic(err)
	} else {
		// We only initialize the table if it doesn't already exist.
		// This should not really impact performance since it only checks
		// during start up.
		if !toktik_db.Migrator().HasTable(&user.User{}) {
			db.InitUserTable(toktik_db)
			log.Println("Database initialized!")
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/signin", DatabaseConnectionMiddleware(dsn, SignInHanlder))
	mux.HandleFunc("/signup", DatabaseConnectionMiddleware(dsn, SignUpHandler))
	mux.HandleFunc("/refresh", RefreshHandler)
	mux.HandleFunc("/logout", LogoutHandler)
	mux.HandleFunc("/", IsAuthHandler)

	// start the server on port 7887
	log.Println("Serving on port 7887")

	handler := cors.New(cors.Options{
		// NOTE(APPY): DON'T FORGET TO REMOVE THIS!
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
