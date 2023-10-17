// This function contains a collection of useful middlewares to reduce code duplication.
// Information attachments are simply done by wrapping the function with an additional
// layer which contributes to the context of the request.

package main

import (
	"context"
	"net/http"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// The DatabaseConnectionMiddleware attachs the following information to the handler:
// 	conn: *gorm.DB - This is a connection to the database.
func DatabaseConnectionMiddleware(dsn string, next Handler) Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		toktik_db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		ctx := context.WithValue(r.Context(), "conn", toktik_db)
		next(w, r.WithContext(ctx))
	}
}
