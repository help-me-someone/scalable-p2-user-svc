package main

import (
	"fmt"
	"log"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

const (
	region = "sgp1"
)

// gorm.DB objects are meant to be reused.
var GORM_CONNECTION_SINGLETON *gorm.DB

func GetDatabaseConnection(username, password, server string) (*gorm.DB, error) {
	if GORM_CONNECTION_SINGLETON == nil {
		dsn := fmt.Sprintf(
			"%s:%s@tcp(%s)/toktik-db?charset=utf8mb4&parseTime=True&loc=Local",
			username,
			password,
			server,
		)
		log.Println("Attemping to get:", dsn)
		connection, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			return nil, err
		} else {
			GORM_CONNECTION_SINGLETON = connection
		}
	}
	return GORM_CONNECTION_SINGLETON, nil
}
