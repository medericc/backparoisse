package middleware

import (
	"net/http"
	"strings"
	"log"
	"github.com/golang-jwt/jwt/v4"
	"golang-backend/config"
)

// Middleware pour vérifier les tokens JWT
func JWTAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Récupérer l'en-tête Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// Vérifier le format du header (Bearer token)
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// Extraire le token
		tokenString := parts[1]

		// Valider le token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Vérifiez que la méthode de signature est bien HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.NewValidationError("Invalid signing method", jwt.ValidationErrorSignatureInvalid)
			}
			return []byte(config.JwtSecret), nil
		})

		// Gérer les erreurs de validation
		if err != nil || !token.Valid {
			log.Println("Invalid token:", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Passer au handler suivant
		next.ServeHTTP(w, r)
	})
}
