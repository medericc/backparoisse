package main

import (
	"fmt"
	"log"
	"net/http"
	"golang-backend/config"
	"golang-backend/handlers"
	
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func main() {
	// Connexion à la base de données
	config.ConnectDB()
	defer config.DB.Close()

	// Initialiser le routeur
	r := mux.NewRouter()

	// Routes API
	r.HandleFunc("/api/articles", handlers.GetArticles).Methods("GET")

	// Appliquer le middleware JWT à CreateArticle
	r.HandleFunc("/api/articles", handlers.CreateArticle).Methods("POST")

	// Routes pour l'authentification
	r.HandleFunc("/api/auth/signup", handlers.SignupHandler).Methods("POST")
	r.HandleFunc("/api/auth/login", handlers.LoginHandler).Methods("POST")

	// Configurer CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	// Lancer le serveur avec CORS
	fmt.Println("API running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", corsHandler.Handler(r)))
}
