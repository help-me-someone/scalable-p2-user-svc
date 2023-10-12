package main

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// Create a struct which reads the username and password from a request.
type Credentials struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
}

// Create a struct which will be encoded to a JWT.
// Embedded registered claims. This provides us with fields like "Expire time", etc...
type Claims struct {
	Username string `json:"username" form:"username"`
	jwt.RegisteredClaims
}

type Handler = func(w http.ResponseWriter, r *http.Request)
