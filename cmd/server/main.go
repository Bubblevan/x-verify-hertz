package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"stablepay-x-verify-hertz/internal/config"
	"stablepay-x-verify-hertz/internal/model"
	"stablepay-x-verify-hertz/internal/service"
	"stablepay-x-verify-hertz/internal/store"
	"stablepay-x-verify-hertz/internal/util"
)

type Server struct {
	verifySvc     *service.VerifyTwitterService
	xOAuthSvc     *service.XOAuthService
	didStore      *store.DIDStore
	tweetStore    *store.TweetStore
	bindingStore  *store.BindingStore
	rewardStore   *store.RewardStore
	xSessionStore *store.XOAuthSessionStore
	xAccountStore *store.XAccountStore
	xBindingStore *store.XBindingStore
}

func main() {
	// Load configuration
	config.Load()

	s := &Server{
		didStore:      store.NewDIDStore(),
		tweetStore:    store.NewTweetStore(),
		bindingStore:  store.NewBindingStore(),
		rewardStore:   store.NewRewardStore(),
		xSessionStore: store.NewXOAuthSessionStore(),
		xAccountStore: store.NewXAccountStore(),
		xBindingStore: store.NewXBindingStore(),
	}
	s.verifySvc = service.NewVerifyTwitterService(s.didStore, s.tweetStore, s.bindingStore, s.rewardStore)
	s.xOAuthSvc = service.NewXOAuthService(s.xSessionStore, s.xAccountStore, s.xBindingStore, s.didStore)

	mux := http.NewServeMux()

	// Mock endpoints (for testing without real X API)
	mux.HandleFunc("/api/v1/mock/did", s.handleMockDID)
	mux.HandleFunc("/api/v1/mock/twitter/tweets", s.handleMockTweet)
	mux.HandleFunc("/api/v1/mock/bindings", s.handleGetBindings)
	mux.HandleFunc("/api/v1/verify/twitter", s.handleVerify) // Legacy mock verify

	// Real X OAuth endpoints
	mux.HandleFunc("/api/v1/x/oauth/start", s.handleXOAuthStart)
	mux.HandleFunc("/api/v1/x/oauth/callback", s.handleXOAuthCallback)
	mux.HandleFunc("/api/v1/x/oauth/status", s.handleXOAuthStatus)
	mux.HandleFunc("/api/v1/x/verify-twitter", s.handleXVerifyTwitter) // Real verify
	mux.HandleFunc("/api/v1/verify", s.handleGetVerifyStatus)

	handler := corsMiddleware(mux)

	port := config.C.Port
	log.Printf("stablepay x verify listening on :%s", port)
	log.Printf("Configuration:")
	log.Printf("  - X Client ID: %s...", truncate(config.C.XClientID, 10))
	log.Printf("  - Frontend URL: %s", config.C.FrontendVerifyURL)
	log.Printf("  - OAuth Callback: %s", config.C.XRedirectURI)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Legacy mock verify endpoint
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.VerifyTwitterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid json")
		return
	}

	resp, errResp := s.verifySvc.Verify(req)
	if errResp != nil {
		writeError(w, http.StatusBadRequest, errResp.Code, errResp.Message)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// X OAuth Start - initiates OAuth flow
func (s *Server) handleXOAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	did := r.URL.Query().Get("did")
	if did == "" {
		writeError(w, http.StatusBadRequest, "missing_param", "did parameter required")
		return
	}

	resp, err := s.xOAuthSvc.StartOAuth(did)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// X OAuth Callback - handles OAuth callback from X
func (s *Server) handleXOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorMsg := r.URL.Query().Get("error")

	if errorMsg != "" {
		// Handle OAuth error from X
		redirectURL := fmt.Sprintf("%s?oauth=failed&reason=%s",
			config.C.FrontendVerifyURL,
			errorMsg,
		)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	if code == "" || state == "" {
		redirectURL := fmt.Sprintf("%s?oauth=failed&reason=missing_code_or_state",
			config.C.FrontendVerifyURL,
		)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	redirectURL, err := s.xOAuthSvc.HandleCallback(code, state)
	if err != nil {
		errorRedirect := fmt.Sprintf("%s?oauth=failed&reason=%s",
			config.C.FrontendVerifyURL,
			err.Error(),
		)
		http.Redirect(w, r, errorRedirect, http.StatusTemporaryRedirect)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

// X OAuth Status - checks if DID is connected to X
func (s *Server) handleXOAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	did := r.URL.Query().Get("did")
	if did == "" {
		writeError(w, http.StatusBadRequest, "missing_param", "did parameter required")
		return
	}

	status, err := s.xOAuthSvc.GetOAuthStatus(did)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// X Verify Twitter - real verification using X API
func (s *Server) handleXVerifyTwitter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DID      string `json:"did"`
		TweetURL string `json:"tweet_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid json")
		return
	}

	// TODO: Implement real X API verify
	// For now, return error indicating this needs X API credentials
	if config.C.XClientID == "" {
		writeError(w, http.StatusServiceUnavailable, "x_api_not_configured",
			"X API not configured. Set X_CLIENT_ID and X_CLIENT_SECRET environment variables.")
		return
	}

	// Placeholder: call the real verification service
	writeError(w, http.StatusNotImplemented, "not_implemented",
		"Real X API verification is being implemented. Please check your X API credentials first.")
}

// Get Verify Status - checks verification status for a DID
func (s *Server) handleGetVerifyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	did := r.URL.Query().Get("did")
	if did == "" {
		writeError(w, http.StatusBadRequest, "missing_param", "did parameter required")
		return
	}

	// Check mock binding first
	if binding, ok := s.bindingStore.GetByDID(did); ok {
		writeJSON(w, http.StatusOK, model.VerifyStatusResponse{
			Verified:      true,
			TwitterHandle: &binding.TwitterHandle,
			RewardTx:      &binding.RewardTx,
		})
		return
	}

	// Check real X binding
	if binding, ok := s.xBindingStore.GetByDID(did); ok {
		writeJSON(w, http.StatusOK, model.VerifyStatusResponse{
			Verified:      true,
			TwitterHandle: &binding.Username,
			RewardTx:      &binding.RewardTx,
		})
		return
	}

	writeJSON(w, http.StatusOK, model.VerifyStatusResponse{
		Verified: false,
	})
}

// Legacy mock endpoints
func (s *Server) handleMockDID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DID           string `json:"did"`
		WalletAddress string `json:"wallet_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid json")
		return
	}

	if !util.IsValidDID(req.DID) {
		writeError(w, http.StatusBadRequest, "invalid_did", "did format invalid")
		return
	}

	s.didStore.Save(model.DIDIdentity{
		DID:           req.DID,
		WalletAddress: req.WalletAddress,
		CreatedAt:     time.Now().UTC(),
	})

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleMockTweet(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, []model.MockTweet{})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.MockCreateTweetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid json")
		return
	}

	handle, _, normalizedURL, err := util.ParseTweetURL(req.TweetURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_url", err.Error())
		return
	}

	tweet := model.MockTweet{
		TweetURL:     normalizedURL,
		AuthorHandle: handle,
		Text:         req.Text,
		IsPublic:     req.IsPublic,
		CreatedAt:    time.Now().UTC(),
	}

	s.tweetStore.Save(tweet)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"tweet":   tweet,
	})
}

func (s *Server) handleGetBindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	did := r.URL.Query().Get("did")
	if did != "" {
		binding, exists := s.bindingStore.GetByDID(did)
		if !exists {
			writeError(w, http.StatusNotFound, "not_found", "binding not found")
			return
		}
		writeJSON(w, http.StatusOK, binding)
		return
	}

	bindings := s.bindingStore.List()
	writeJSON(w, http.StatusOK, bindings)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, model.ErrorResponse{
		Success: false,
		Code:    code,
		Message: message,
	})
}
