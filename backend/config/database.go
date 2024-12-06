package config

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

var DB *sql.DB

// ConnectDB établit une connexion à PostgreSQL
func ConnectDB() {
	var err error
	connStr := "postgres://postgres:bleublanctour1@localhost/paroisse?sslmode=disable"
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	log.Println("Connected to the database successfully!")
}

