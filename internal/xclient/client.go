package xclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stablepay-x-verify-hertz/internal/config"
)

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// BuildAuthorizeURL builds the X OAuth authorization URL with PKCE
func (c *Client) BuildAuthorizeURL(state, codeChallenge string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", config.C.XClientID)
	params.Set("redirect_uri", config.C.XRedirectURI)
	params.Set("scope", config.C.XOAuthScopes)
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	return fmt.Sprintf("%s?%s", config.C.XAuthorizeURL, params.Encode())
}

// TokenResponse represents the token endpoint response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// ExchangeCodeForToken exchanges authorization code for access token
func (c *Client) ExchangeCodeForToken(code, codeVerifier string) (*TokenResponse, error) {
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", code)
	params.Set("redirect_uri", config.C.XRedirectURI)
	params.Set("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", config.C.XTokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// For confidential clients, use Basic Auth
	if config.C.XClientSecret != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(config.C.XClientID + ":" + config.C.XClientSecret))
		req.Header.Set("Authorization", "Basic "+auth)
	} else {
		// For public clients, client_id is in the body
		params.Set("client_id", config.C.XClientID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// RefreshAccessToken refreshes the access token using refresh token
func (c *Client) RefreshAccessToken(refreshToken string) (*TokenResponse, error) {
	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", config.C.XTokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Basic Auth for confidential clients
	if config.C.XClientSecret != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(config.C.XClientID + ":" + config.C.XClientSecret))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed: %s - %s", resp.Status, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// UserInfo represents the X user information
type UserInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Username   string `json:"username"`
	Protected  bool   `json:"protected"`
	Verified   bool   `json:"verified,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
}

// UsersMeResponse represents the response from /2/users/me
type UsersMeResponse struct {
	Data UserInfo `json:"data"`
}

// GetMyUser fetches the authenticated user's information
func (c *Client) GetMyUser(accessToken string) (*UserInfo, error) {
	url := fmt.Sprintf("%s/users/me", config.C.XAPIBaseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user failed: %s - %s", resp.Status, string(body))
	}

	var userResp UsersMeResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, err
	}

	return &userResp.Data, nil
}

// Tweet represents a single tweet
type Tweet struct {
	ID        string `json:"id"`
	Text      string `json:"text"`
	AuthorID  string `json:"author_id"`
	CreatedAt string `json:"created_at,omitempty"`
}

// User represents user information in tweet expansion
type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Protected bool   `json:"protected"`
}

// TweetResponse represents the response from /2/tweets/{id}
type TweetResponse struct {
	Data      Tweet   `json:"data"`
	Includes  struct {
		Users []User `json:"users"`
	} `json:"includes"`
}

// GetTweetByID fetches a tweet by its ID
func (c *Client) GetTweetByID(tweetID, accessToken string) (*Tweet, *User, error) {
	apiURL := fmt.Sprintf("%s/tweets/%s?tweet.fields=author_id,created_at,text&expansions=author_id&user.fields=id,username,protected",
		config.C.XAPIBaseURL, tweetID)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, fmt.Errorf("tweet not found")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("get tweet failed: %s - %s", resp.Status, string(body))
	}

	var tweetResp TweetResponse
	if err := json.Unmarshal(body, &tweetResp); err != nil {
		return nil, nil, err
	}

	var author *User
	for i := range tweetResp.Includes.Users {
		if tweetResp.Includes.Users[i].ID == tweetResp.Data.AuthorID {
			author = &tweetResp.Includes.Users[i]
			break
		}
	}

	return &tweetResp.Data, author, nil
}
