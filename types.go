package main

import "github.com/golang-jwt/jwt/v5"

// Create a struct which reads the username and password from a request.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Create a struct which will be encoded to a JWT.
type Claims struct {
	Username string `json:"username"`
	// Embedded type. This provides us with fields like "Expire time", etc...
	jwt.RegisteredClaims
}
