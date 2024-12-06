package config

import (
    "crypto/rand"
    "encoding/base64"
    "log"
)

// Exporter JwtSecret
var JwtSecret = generateSecretKey()

// Fonction pour générer une clé secrète
func generateSecretKey() string {
    key := make([]byte, 32) // 32 bytes pour 256-bit security
    _, err := rand.Read(key)
    if err != nil {
        log.Fatalf("Erreur lors de la génération de la clé secrète : %v", err)
    }
    return base64.StdEncoding.EncodeToString(key)
}
