package idclogin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/common-fate/clio"
	"github.com/google/uuid"
)

type ProviderLoginInput struct {
	IssuerURL      string
	ClientID       string
	Scopes         []string
	BrowserProfile string
}

type ProviderLoginOutput struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int
}

// OIDCDiscovery holds endpoints from a standard OpenID Connect discovery document.
type OIDCDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
}

// DiscoverOIDC fetches the OpenID Connect discovery document from the issuer's
// well-known configuration endpoint.
func DiscoverOIDC(ctx context.Context, issuerURL string) (*OIDCDiscovery, error) {
	discoveryURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	clio.Debugw("fetching OIDC discovery document", "url", discoveryURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building OIDC discovery request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC discovery from %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned HTTP %d from %s", resp.StatusCode, discoveryURL)
	}

	var discovery OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("decoding OIDC discovery from %s: %w", discoveryURL, err)
	}

	if discovery.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery from %s missing authorization_endpoint", discoveryURL)
	}
	if discovery.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery from %s missing token_endpoint", discoveryURL)
	}

	return &discovery, nil
}

// ProviderLogin performs an OAuth Authorization Code + PKCE flow against a
// generic OIDC provider (not AWS SSO specific). It opens the user's browser,
// waits for the authorization callback, and exchanges the code for tokens.
func ProviderLogin(ctx context.Context, input ProviderLoginInput) (*ProviderLoginOutput, error) {
	discovery, err := DiscoverOIDC(ctx, input.IssuerURL)
	if err != nil {
		return nil, err
	}

	callbackResult := make(chan providerCallbackResult, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start local OAuth callback server: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("failed to generate PKCE code verifier: %w", err)
	}
	codeChallenge := computeCodeChallenge(codeVerifier)

	state := uuid.New().String()

	srv := &http.Server{
		Handler:      newProviderCallbackHandler(state, callbackResult),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			clio.Debugf("OAuth callback server error: %s", err)
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	authorizeURL, err := buildProviderAuthorizeURL(discovery.AuthorizationEndpoint, input.ClientID, callbackURL, state, codeChallenge, input.Scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to build authorize URL: %w", err)
	}

	if err := OpenBrowserWithFallbackMessage(authorizeURL, input.BrowserProfile); err != nil {
		return nil, err
	}

	clio.Info("Awaiting authentication in the browser")
	clio.Info("You will be prompted to authenticate and approve access")

	var result providerCallbackResult
	select {
	case result = <-callbackResult:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(authorizationCallbackTimeout):
		return nil, errors.New("timed out waiting for authorization callback")
	}

	if result.err != nil {
		return nil, fmt.Errorf("authorization failed: %w", result.err)
	}

	output, err := exchangeCodeForToken(ctx, discovery.TokenEndpoint, tokenExchangeInput{
		Code:         result.code,
		ClientID:     input.ClientID,
		RedirectURI:  callbackURL,
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		return nil, err
	}

	return output, nil
}

type providerCallbackResult struct {
	code string
	err  error
}

const providerCallbackSuccessHTML = `<!DOCTYPE html>
<html>
<head><title>Granted - Authentication Successful</title></head>
<body style="font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f8f9fa;">
<div style="text-align: center; padding: 2rem;">
<h1 style="color: #16a34a;">Authentication Successful</h1>
<p>You have successfully authenticated with your access provider.</p>
<p>You can close this window and return to your terminal.</p>
</div>
</body>
</html>`

func newProviderCallbackHandler(expectedState string, result chan<- providerCallbackResult) http.Handler {
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var handled bool
		once.Do(func() {
			handled = true
			query := r.URL.Query()

			if errParam := query.Get("error"); errParam != "" {
				errDesc := query.Get("error_description")
				writeErrorPage(w, errParam, errDesc)
				result <- providerCallbackResult{err: fmt.Errorf("%s: %s", errParam, errDesc)}
				return
			}

			code := query.Get("code")
			st := query.Get("state")

			if st != expectedState {
				writeErrorPage(w, "state_mismatch", "The state parameter did not match. This may indicate a CSRF attack.")
				result <- providerCallbackResult{err: errors.New("OAuth state parameter mismatch")}
				return
			}

			if code == "" {
				writeErrorPage(w, "missing_code", "No authorization code was received.")
				result <- providerCallbackResult{err: errors.New("no authorization code received")}
				return
			}

			setSecurityHeaders(w)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(providerCallbackSuccessHTML))
			result <- providerCallbackResult{code: code}
		})

		if !handled {
			http.Error(w, "Authorization already processed", http.StatusConflict)
		}
	})
	return mux
}

func buildProviderAuthorizeURL(authorizationEndpoint, clientID, redirectURI, state, codeChallenge string, scopes []string) (string, error) {
	u, err := url.Parse(authorizationEndpoint)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("scope", strings.Join(scopes, " "))
	u.RawQuery = q.Encode()

	return u.String(), nil
}

type tokenExchangeInput struct {
	Code         string
	ClientID     string
	RedirectURI  string
	CodeVerifier string
}

type tokenExchangeResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func exchangeCodeForToken(ctx context.Context, tokenEndpoint string, input tokenExchangeInput) (*ProviderLoginOutput, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {input.Code},
		"client_id":     {input.ClientID},
		"redirect_uri":  {input.RedirectURI},
		"code_verifier": {input.CodeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token exchange response: %w", err)
	}

	var tokenResp tokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decoding token exchange response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("token exchange error: %s: %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
	}

	if tokenResp.AccessToken == "" {
		return nil, errors.New("token exchange returned empty access_token")
	}

	return &ProviderLoginOutput{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}
