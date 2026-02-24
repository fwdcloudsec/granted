package idclogin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/google/uuid"
)

// authorizationCallbackTimeout is the maximum time to wait for the user to
// complete browser-based authentication before giving up.
const authorizationCallbackTimeout = 5 * time.Minute

// LoginWithAuthorizationCode performs an Authorization Code Grant with PKCE flow
// to retrieve an SSO token. This provides a smoother UX than the device code flow
// by skipping the manual code entry step.
func LoginWithAuthorizationCode(ctx context.Context, cfg aws.Config, startUrl string, scopes []string) (*securestorage.SSOToken, error) {
	if cfg.Region == "" {
		return nil, errors.New("AWS region is required for authorization code flow")
	}

	ssooidcClient := ssooidc.NewFromConfig(cfg)

	// The authorization code flow uses "sso:account:access" as the default scope,
	// which is the modern scope for IAM Identity Center. This differs from the
	// device code flow's legacy "sso-portal:*" default.
	if len(scopes) == 0 {
		scopes = []string{"sso:account:access"}
	}

	// Bind the listener first to reserve a port for the redirect URI.
	// We defer starting the HTTP server until after RegisterClient succeeds.
	callbackResult := make(chan authCallbackResult, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start local OAuth callback server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", port)

	state := uuid.New().String()

	// Register client with authorization_code grant type.
	//
	// The redirect URI for registration uses the portless form. Per RFC 8252
	// Section 7.3, authorization servers MUST allow any port to be specified for
	// loopback redirect URIs. AWS IAM Identity Center implements this exemption:
	// the portless URI is registered, but the actual redirect uses a port-specific URI.
	client, err := ssooidcClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName:   aws.String("Granted CLI"),
		ClientType:   aws.String("public"),
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		RedirectUris: []string{"http://127.0.0.1/oauth/callback"},
		IssuerUrl:    aws.String(startUrl),
		Scopes:       scopes,
	})
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("failed to register OIDC client: %w", err)
	}

	// Now that registration succeeded, start the HTTP server to receive the callback.
	srv := &http.Server{
		Handler:      newCallbackHandler(state, callbackResult),
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

	// Determine the authorization endpoint. The RegisterClient API may return it,
	// but many regions don't include it in the response. Fall back to the standard
	// regional endpoint pattern used by the AWS CLI.
	authorizationEndpoint := fmt.Sprintf("https://oidc.%s.amazonaws.com/authorize", cfg.Region)
	if client.AuthorizationEndpoint != nil && *client.AuthorizationEndpoint != "" {
		authorizationEndpoint = *client.AuthorizationEndpoint
	}

	// Generate PKCE code verifier and challenge
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE code verifier: %w", err)
	}
	codeChallenge := computeCodeChallenge(codeVerifier)

	// Construct the authorization URL
	authorizeURL, err := buildAuthorizeURL(authorizationEndpoint, *client.ClientId, redirectURI, state, codeChallenge, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to build authorize URL: %w", err)
	}

	// Open browser with fallback message
	if err := OpenBrowserWithFallbackMessage(authorizeURL); err != nil {
		return nil, err
	}

	clio.Info("Awaiting AWS authentication in the browser")
	clio.Info("You will be prompted to authenticate and approve access")

	// Wait for the callback
	var result authCallbackResult
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

	// Exchange the authorization code for tokens
	token, err := ssooidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     client.ClientId,
		ClientSecret: client.ClientSecret,
		GrantType:    aws.String("authorization_code"),
		Code:         aws.String(result.code),
		CodeVerifier: aws.String(codeVerifier),
		RedirectUri:  aws.String(redirectURI),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code for token: %w", err)
	}

	ssoToken := securestorage.SSOToken{
		AccessToken:           *token.AccessToken,
		Expiry:                time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		ClientID:              *client.ClientId,
		ClientSecret:          *client.ClientSecret,
		RegistrationExpiresAt: time.Unix(client.ClientSecretExpiresAt, 0),
		RefreshToken:          token.RefreshToken,
		Region:                cfg.Region,
	}

	return &ssoToken, nil
}

type authCallbackResult struct {
	code string
	err  error
}

type callbackPageData struct {
	Error       string
	Description string
}

var callbackErrorTmpl = template.Must(template.New("error").Parse(`<!DOCTYPE html>
<html>
<head><title>Granted - Authentication Failed</title></head>
<body style="font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f8f9fa;">
<div style="text-align: center; padding: 2rem;">
<h1 style="color: #dc2626;">Authentication Failed</h1>
<p>Error: {{.Error}}</p>
<p>{{.Description}}</p>
<p>Please close this window and try again.</p>
</div>
</body>
</html>`))

const callbackSuccessHTML = `<!DOCTYPE html>
<html>
<head><title>Granted - Authentication Successful</title></head>
<body style="font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f8f9fa;">
<div style="text-align: center; padding: 2rem;">
<h1 style="color: #16a34a;">Authentication Successful</h1>
<p>You have successfully authenticated with AWS IAM Identity Center.</p>
<p>You can close this window and return to your terminal.</p>
</div>
</body>
</html>`

// setSecurityHeaders sets defensive HTTP headers on callback responses.
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func writeErrorPage(w http.ResponseWriter, errCode, description string) {
	setSecurityHeaders(w)
	w.WriteHeader(http.StatusBadRequest)
	_ = callbackErrorTmpl.Execute(w, callbackPageData{
		Error:       errCode,
		Description: description,
	})
}

func newCallbackHandler(expectedState string, result chan<- authCallbackResult) http.Handler {
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		// Only accept GET requests per OAuth 2.0 spec
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Only process the first callback request. Subsequent requests
		// (browser retries, favicon fetches, attacker probes) are ignored.
		var handled bool
		once.Do(func() {
			handled = true
			query := r.URL.Query()

			if errParam := query.Get("error"); errParam != "" {
				errDesc := query.Get("error_description")
				writeErrorPage(w, errParam, errDesc)
				result <- authCallbackResult{err: fmt.Errorf("%s: %s", errParam, errDesc)}
				return
			}

			code := query.Get("code")
			state := query.Get("state")

			if state != expectedState {
				writeErrorPage(w, "state_mismatch", "The state parameter did not match. This may indicate a CSRF attack.")
				result <- authCallbackResult{err: errors.New("OAuth state parameter mismatch")}
				return
			}

			if code == "" {
				writeErrorPage(w, "missing_code", "No authorization code was received.")
				result <- authCallbackResult{err: errors.New("no authorization code received")}
				return
			}

			setSecurityHeaders(w)
			w.WriteHeader(http.StatusOK)
			// callbackSuccessHTML is a static string with no interpolation, safe to write directly
			_, _ = w.Write([]byte(callbackSuccessHTML))
			result <- authCallbackResult{code: code}
		})

		if !handled {
			http.Error(w, "Authorization already processed", http.StatusConflict)
		}
	})
	return mux
}

// generateCodeVerifier generates a cryptographically random code verifier
// per RFC 7636. It produces a 43-128 character string from the unreserved character set.
func generateCodeVerifier() (string, error) {
	// 32 bytes -> 43 base64url characters (no padding)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// computeCodeChallenge computes the S256 code challenge from the verifier per RFC 7636.
func computeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func buildAuthorizeURL(authorizationEndpoint, clientID, redirectURI, state, codeChallenge string, scopes []string) (string, error) {
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
