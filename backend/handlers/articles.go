package handlers

import (
	"encoding/json"
	"log"
	"io"
	"bytes"
	"database/sql"
	"net/http"
	"time"  // Pour gérer l'expiration du token
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v4"
// Pour la gestion des JWT
	"golang-backend/models"
	
	"golang-backend/config"
	
	
)


// loginHandler gère la connexion de l'utilisateur
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        var creds struct {
            Email    string `json:"email"`
            Password string `json:"password"`
        }

        // Parse la requête JSON
        if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
            log.Println("Erreur de décodage JSON:", err)
            http.Error(w, "Bad request", http.StatusBadRequest)
            return
        }

        // Vérification des champs email et mot de passe
        if creds.Email == "" || creds.Password == "" {
            http.Error(w, "Email et mot de passe sont requis", http.StatusBadRequest)
            return
        }

        // Vérifier si l'email existe dans la base de données
        var storedPassword string
        var userID int
        var username string
        err := config.DB.QueryRow("SELECT id, username, password FROM users WHERE email = $1", creds.Email).Scan(&userID, &username, &storedPassword)
        if err != nil {
            if err == sql.ErrNoRows {
                http.Error(w, "Email ou mot de passe incorrect", http.StatusUnauthorized)
                return
            }
            log.Println("Erreur lors de la vérification de l'email:", err)
            http.Error(w, "Erreur lors de la vérification de l'email", http.StatusInternalServerError)
            return
        }

        // Vérifier le mot de passe
        if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(creds.Password)); err != nil {
            http.Error(w, "Email ou mot de passe incorrect", http.StatusUnauthorized)
            return
        }

        // Générer un token JWT
        token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
            "user_id":  userID,
            "username": username,
            "email":    creds.Email,
            "exp":      time.Now().Add(time.Hour * 24).Unix(),  // Expiration du token dans 24 heures
        })

        // Utilisez jwtSecret pour signer le token
		tokenString, err := token.SignedString([]byte(config.JwtSecret)) // Utilisation de config.JwtSecret
        if err != nil {
            log.Println("Erreur lors de la génération du token:", err)
            http.Error(w, "Erreur lors de la génération du token", http.StatusInternalServerError)
            return
        }

        // Retourner la réponse avec le token JWT
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "message": "Connexion réussie",
            "token":   tokenString,
            "user": map[string]interface{}{
                "id":       userID,
                "username": username,
                "email":    creds.Email,
            },
        })
    } else {
        http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
    }
}
func SignupHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        var creds struct {
            Email    string `json:"email"`
            Password string `json:"password"`
            Username string `json:"username"`
        }

        // Parse la requête JSON
        if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
            log.Println("Erreur de décodage JSON:", err)
            http.Error(w, "Bad request", http.StatusBadRequest)
            return
        }

        // Ajoute un log pour voir les données reçues
        log.Printf("Données reçues: email=%s, password=%s, username=%s", creds.Email, creds.Password, creds.Username)

        // Vérification des champs email, mot de passe et username
        if creds.Email == "" || creds.Password == "" || creds.Username == "" {
            log.Println("Email, mot de passe ou pseudo manquant")
            http.Error(w, "Email, mot de passe et pseudo sont requis", http.StatusBadRequest)
            return
        }

        // Hash du mot de passe avant de l'enregistrer
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
        if err != nil {
            log.Println("Erreur de hachage du mot de passe:", err)
            http.Error(w, "Erreur de hachage du mot de passe", http.StatusInternalServerError)
            return
        }

        // Vérifier si l'email existe déjà dans la base de données
        var existingUser struct {
            ID int
        }
        err = config.DB.QueryRow("SELECT id FROM users WHERE email = $1", creds.Email).Scan(&existingUser.ID)
        if err != nil && err != sql.ErrNoRows {
            log.Println("Erreur lors de la vérification de l'email:", err)
            http.Error(w, "Erreur lors de la vérification de l'email", http.StatusInternalServerError)
            return
        }
        if existingUser.ID != 0 {
            log.Println("Email déjà utilisé:", creds.Email)
            http.Error(w, "Cet email est déjà utilisé", http.StatusConflict)
            return
        }

        // Vérifier si le username existe déjà dans la base de données
        err = config.DB.QueryRow("SELECT id FROM users WHERE username = $1", creds.Username).Scan(&existingUser.ID)
        if err != nil && err != sql.ErrNoRows {
            log.Println("Erreur lors de la vérification du pseudo:", err)
            http.Error(w, "Erreur lors de la vérification du pseudo", http.StatusInternalServerError)
            return
        }
        if existingUser.ID != 0 {
            log.Println("Pseudo déjà utilisé:", creds.Username)
            http.Error(w, "Ce pseudo est déjà utilisé", http.StatusConflict)
            return
        }

        // Enregistrer l'utilisateur dans la base de données
        _, err = config.DB.Exec("INSERT INTO users (email, password, username) VALUES ($1, $2, $3)", creds.Email, string(hashedPassword), creds.Username)
        if err != nil {
            log.Println("Erreur lors de l'inscription:", err)
            http.Error(w, "Erreur lors de l'inscription", http.StatusInternalServerError)
            return
        }

        // Retourner une réponse de succès
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{"message": "Utilisateur créé avec succès"})
    } else {
        log.Println("Méthode non autorisée")
        http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
    }
}


// Fonction pour créer un article
func CreateArticle(w http.ResponseWriter, r *http.Request) {
    log.Println("CreateArticle endpoint hit")

    // Lire et loguer le corps brut de la requête
    body, err := io.ReadAll(r.Body)
    if err != nil {
        log.Println("Error reading request body:", err)
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    log.Println("Raw request body:", string(body))

    // Décoder le corps de la requête en Article
    var article models.Article
    decoder := json.NewDecoder(bytes.NewReader(body))
    if err := decoder.Decode(&article); err != nil {
        log.Println("Error decoding JSON:", err)
        http.Error(w, "Invalid JSON format: "+err.Error(), http.StatusBadRequest)
        return
    }

    // Log des données après décodage
    log.Printf("Decoded article: %+v\n", article)

    // Validation des champs
    if article.Title == "" || article.Content == "" || article.Username == "" || article.CategoryNAME == "" {
        log.Println("Missing required fields in the request")
        http.Error(w, "Missing required fields", http.StatusBadRequest)
        return
    }

    // Log avant l'exécution de la requête SQL
    log.Println("Preparing to execute query:", "INSERT INTO articles (title, content, image_url, published_at, username, category_name) VALUES ($1, $2, $3, $4, $5, $6)")

    // Insertion dans la base de données
    var id int
    err = config.DB.QueryRow("INSERT INTO articles (title, content, image_url, published_at, username, category_name) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id", 
                              article.Title, article.Content, article.ImageURL, article.PublishedAt, article.Username, article.CategoryNAME).Scan(&id)
    if err != nil {
        log.Printf("Error executing query: %v\n", err) // Log détaillé de l'erreur
        http.Error(w, "Error creating article: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Log après insertion réussie
    log.Println("Article inserted successfully with ID:", id)

    // Mise à jour de l'ID de l'article
    article.ID = id

    // Retourner l'article créé
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    if err := json.NewEncoder(w).Encode(article); err != nil {
        log.Println("Error encoding response JSON:", err)
        http.Error(w, "Error encoding response", http.StatusInternalServerError)
    }
}



// Fonction pour récupérer les articles
func GetArticles(w http.ResponseWriter, r *http.Request) {
	// Exécuter la requête pour récupérer les articles depuis la base de données
	rows, err := config.DB.Query("SELECT id, title, content, image_url, published_at, username, category_name  FROM articles")
	if err != nil {
		log.Println("Error retrieving articles:", err)
		http.Error(w, "Error retrieving articles", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var articles []models.Article
	for rows.Next() {
		var article models.Article
		// Scanner les résultats de la requête dans l'objet Article
		if err := rows.Scan(&article.ID, &article.Title, &article.Content, &article.ImageURL, &article.PublishedAt, &article.Username, &article.CategoryNAME,); err != nil {
			log.Println("Error scanning row:", err)
			http.Error(w, "Error processing article data", http.StatusInternalServerError)
			return
		}
		articles = append(articles, article)
	}

	// Vérification si une erreur est survenue pendant l'itération des lignes
	if err := rows.Err(); err != nil {
		log.Println("Error with rows:", err)
		http.Error(w, "Error processing articles", http.StatusInternalServerError)
		return
	}

	// Retourner les articles en réponse
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(articles)
}

