package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	XClientID           string
	XClientSecret       string
	XRedirectURI        string
	XOAuthScopes        string
	XAuthorizeURL       string
	XTokenURL           string
	XAPIBaseURL         string
	XVerifyTweetTemplate string
	FrontendVerifyURL   string
	EncryptionKey       string
	Port                string
}

var C *Config

func Load() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	C = &Config{
		XClientID:           getEnv("X_CLIENT_ID", ""),
		XClientSecret:       getEnv("X_CLIENT_SECRET", ""),
		XRedirectURI:        getEnv("X_REDIRECT_URI", "http://localhost:8080/api/v1/x/oauth/callback"),
		XOAuthScopes:        getEnv("X_OAUTH_SCOPES", "tweet.read users.read offline.access"),
		XAuthorizeURL:       getEnv("X_AUTHORIZE_URL", "https://x.com/i/oauth2/authorize"),
		XTokenURL:           getEnv("X_TOKEN_URL", "https://api.x.com/2/oauth2/token"),
		XAPIBaseURL:         getEnv("X_API_BASE_URL", "https://api.x.com/2"),
		XVerifyTweetTemplate: getEnv("X_VERIFY_TWEET_TEMPLATE", "I'm verifying my StablePay DID: {DID}"),
		FrontendVerifyURL:   getEnv("FRONTEND_VERIFY_URL", "http://127.0.0.1:3000/verify"),
		EncryptionKey:       getEnv("ENCRYPTION_KEY", ""),
		Port:                getEnv("PORT", "8080"),
	}

	if C.XClientID == "" || C.XClientSecret == "" {
		log.Println("WARNING: X_CLIENT_ID or X_CLIENT_SECRET not set. OAuth will not work.")
	}

	if C.EncryptionKey == "" {
		log.Println("WARNING: ENCRYPTION_KEY not set. Using fallback (INSECURE for production).")
		C.EncryptionKey = "your-32-byte-encryption-key-here!!"
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
