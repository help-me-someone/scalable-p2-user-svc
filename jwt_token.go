package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Cookie lifetime, 15 minutes.
const TOKEN_LIFE_TIME = 1

func ValidateJWTTOken(r *http.Request) (*Claims, error) {
	// Obtain the session token.
	cookie, err := r.Cookie("token")
	if err != nil {
		return nil, err
	}

	// Get the JWT string from the cookie
	tokenString := cookie.Value

	claims := &Claims{}

	// Parse the JWT and store it inside claims.
	// Will fail in two cases:
	// - Expired
	// - Signature does not match.
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		// We use the same key that was responsible for creating the token.
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("Invalid token.")
	}

	return claims, nil
}

func CreateJWTToken(creds *Credentials) (string, time.Time, error) {

	// Declare the expiration time of the token. (5 minutes)
	expirationTime := time.Now().Add(TOKEN_LIFE_TIME * time.Minute)

	claims := &Claims{
		Username: creds.Username, RegisteredClaims: jwt.RegisteredClaims{
			// Expressed as unix miliseconds (JWL specification)
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Declare the token with the algorithm used for signing.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", time.Now(), err
	}

	return tokenString, expirationTime, nil
}

func RenewToken(claims *Claims) (string, time.Time, error) {
	// Compute new expiration time.
	expirationTime := time.Now().Add(TOKEN_LIFE_TIME * time.Minute)

	// Change to expire field on the claim so the
	// token we create expires at the new time given.
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)

	// Create a new token with the same user, but differrent expired time.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token.
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", time.Now(), err
	}

	return tokenString, expirationTime, nil
}

// A decorator which makes sure that the user is logged in.
func NeedAuth(handler Handler) Handler {
	return func(wr http.ResponseWriter, re *http.Request) {
		// Authenticate.
		_, err := ValidateJWTTOken(re)
		if err != nil {
			switch err {
			case http.ErrNoCookie:
				wr.WriteHeader(http.StatusUnauthorized)
			case jwt.ErrSignatureInvalid:
				wr.WriteHeader(http.StatusUnauthorized)
			case fmt.Errorf("Invalid token."): // This is kind of evil...
				wr.WriteHeader(http.StatusUnauthorized)
			default:
				wr.WriteHeader(http.StatusBadRequest)
			}
			return
		}

		handler(wr, re)
	}
}
