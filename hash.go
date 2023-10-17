// This file holds the functions for hasing passwords.
// Reference: https://gowebexamples.com/password-hashing/

package main

import "golang.org/x/crypto/bcrypt"

// HashPassword returns the hashed value of the password.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash checks the hashed password against its
// possible plaintext equivalent. It returns true if they match.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
