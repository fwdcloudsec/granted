package idclogin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCodeVerifier(t *testing.T) {
	verifier, err := generateCodeVerifier()
	require.NoError(t, err)

	// RFC 7636: code verifier must be 43-128 characters
	assert.GreaterOrEqual(t, len(verifier), 43)
	assert.LessOrEqual(t, len(verifier), 128)

	// Should be base64url encoded (no padding)
	assert.NotContains(t, verifier, "=")
	assert.NotContains(t, verifier, "+")
	assert.NotContains(t, verifier, "/")

	// Two verifiers should be different (randomness check)
	verifier2, err := generateCodeVerifier()
	require.NoError(t, err)
	assert.NotEqual(t, verifier, verifier2)
}

func TestComputeCodeChallenge(t *testing.T) {
	// RFC 7636 Appendix B known test vector
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeCodeChallenge(verifier)

	// Expected value from RFC 7636 Appendix B
	assert.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge)

	// Challenge should not contain padding
	assert.NotContains(t, challenge, "=")
}

func TestBuildAuthorizeURL(t *testing.T) {
	url, err := buildAuthorizeURL(
		"https://oidc.us-west-2.amazonaws.com/authorize",
		"client-123",
		"http://127.0.0.1:12345/oauth/callback",
		"state-uuid",
		"challenge-value",
		[]string{"sso:account:access"},
	)
	require.NoError(t, err)

	assert.Contains(t, url, "response_type=code")
	assert.Contains(t, url, "client_id=client-123")
	assert.Contains(t, url, "redirect_uri=")
	assert.Contains(t, url, "state=state-uuid")
	assert.Contains(t, url, "code_challenge=challenge-value")
	assert.Contains(t, url, "code_challenge_method=S256")
	assert.Contains(t, url, "scope=sso%3Aaccount%3Aaccess")
	// Ensure it's "scope" (singular per RFC 6749), not "scopes"
	assert.NotContains(t, url, "scopes=")
}

func TestCallbackHandler_Success(t *testing.T) {
	result := make(chan authCallbackResult, 1)
	handler := newCallbackHandler("expected-state", result)

	req := httptest.NewRequest("GET", "/oauth/callback?code=auth-code-123&state=expected-state", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Authentication Successful")
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "default-src 'none'; style-src 'unsafe-inline'", w.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))

	r := <-result
	assert.NoError(t, r.err)
	assert.Equal(t, "auth-code-123", r.code)
}

func TestCallbackHandler_StateMismatch(t *testing.T) {
	result := make(chan authCallbackResult, 1)
	handler := newCallbackHandler("expected-state", result)

	req := httptest.NewRequest("GET", "/oauth/callback?code=auth-code-123&state=wrong-state", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Authentication Failed")

	r := <-result
	assert.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "state parameter mismatch")
}

func TestCallbackHandler_OAuthError(t *testing.T) {
	result := make(chan authCallbackResult, 1)
	handler := newCallbackHandler("expected-state", result)

	req := httptest.NewRequest("GET", "/oauth/callback?error=access_denied&error_description=User+denied+access", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Authentication Failed")

	r := <-result
	assert.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "access_denied")
}

func TestCallbackHandler_MissingCode(t *testing.T) {
	result := make(chan authCallbackResult, 1)
	handler := newCallbackHandler("expected-state", result)

	req := httptest.NewRequest("GET", "/oauth/callback?state=expected-state", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	r := <-result
	assert.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "no authorization code received")
}

func TestCallbackHandler_XSSPrevention(t *testing.T) {
	result := make(chan authCallbackResult, 1)
	handler := newCallbackHandler("expected-state", result)

	// Attempt XSS via error parameters
	req := httptest.NewRequest("GET", "/oauth/callback?error=<script>alert(1)</script>&error_description=<img+onerror=alert(1)+src=x>", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	body := w.Body.String()
	// html/template should escape the XSS payloads so they render as text, not HTML
	assert.NotContains(t, body, "<script>")
	assert.NotContains(t, body, "<img ")
	// The escaped versions should be present
	assert.Contains(t, body, "&lt;script&gt;")
	assert.Contains(t, body, "&lt;img")
}

func TestCallbackHandler_DuplicateRequest(t *testing.T) {
	result := make(chan authCallbackResult, 1)
	handler := newCallbackHandler("expected-state", result)

	// First request succeeds
	req1 := httptest.NewRequest("GET", "/oauth/callback?code=auth-code-123&state=expected-state", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)
	r := <-result
	assert.NoError(t, r.err)
	assert.Equal(t, "auth-code-123", r.code)

	// Second request gets 409 Conflict (not blocked/hanging)
	req2 := httptest.NewRequest("GET", "/oauth/callback?code=another-code&state=expected-state", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusConflict, w2.Code)
}

func TestCallbackHandler_MethodNotAllowed(t *testing.T) {
	result := make(chan authCallbackResult, 1)
	handler := newCallbackHandler("expected-state", result)

	// POST should be rejected
	req := httptest.NewRequest("POST", "/oauth/callback?code=auth-code-123&state=expected-state", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestIsHeadlessEnvironment(t *testing.T) {
	// This test verifies the function doesn't panic and returns a value.
	// We can't meaningfully test environment detection without modifying
	// the environment, which would affect other tests.
	_ = IsHeadlessEnvironment()
}
