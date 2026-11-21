package idclogin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscoverOIDC(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/.well-known/openid-configuration", r.URL.Path)
			_, _ = w.Write([]byte(`{
				"authorization_endpoint": "https://issuer.example.com/authorize",
				"token_endpoint": "https://issuer.example.com/token",
				"userinfo_endpoint": "https://issuer.example.com/userinfo"
			}`))
		}))
		defer srv.Close()

		d, err := DiscoverOIDC(context.Background(), srv.URL)
		assert.NoError(t, err)
		if assert.NotNil(t, d) {
			assert.Equal(t, "https://issuer.example.com/authorize", d.AuthorizationEndpoint)
			assert.Equal(t, "https://issuer.example.com/token", d.TokenEndpoint)
		}
	})

	t.Run("trims trailing slash on issuer", func(t *testing.T) {
		var requestedPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestedPath = r.URL.Path
			_, _ = w.Write([]byte(`{"authorization_endpoint":"a","token_endpoint":"b"}`))
		}))
		defer srv.Close()

		_, err := DiscoverOIDC(context.Background(), srv.URL+"/")
		assert.NoError(t, err)
		assert.Equal(t, "/.well-known/openid-configuration", requestedPath)
	})

	t.Run("missing authorization_endpoint", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"token_endpoint":"b"}`))
		}))
		defer srv.Close()

		_, err := DiscoverOIDC(context.Background(), srv.URL)
		assert.ErrorContains(t, err, "missing authorization_endpoint")
	})

	t.Run("missing token_endpoint", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"authorization_endpoint":"a"}`))
		}))
		defer srv.Close()

		_, err := DiscoverOIDC(context.Background(), srv.URL)
		assert.ErrorContains(t, err, "missing token_endpoint")
	})

	t.Run("non-200 status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		_, err := DiscoverOIDC(context.Background(), srv.URL)
		assert.ErrorContains(t, err, "500")
	})
}

func TestBuildProviderAuthorizeURL(t *testing.T) {
	got, err := buildProviderAuthorizeURL("https://issuer.example.com/authorize", "client-1", "http://127.0.0.1:1234/callback", "state-1", "challenge-1", []string{"openid", "profile"})
	assert.NoError(t, err)

	u, err := url.Parse(got)
	assert.NoError(t, err)

	q := u.Query()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "client-1", q.Get("client_id"))
	assert.Equal(t, "http://127.0.0.1:1234/callback", q.Get("redirect_uri"))
	assert.Equal(t, "state-1", q.Get("state"))
	assert.Equal(t, "challenge-1", q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, "openid profile", q.Get("scope"))
}

func TestBuildProviderAuthorizeURL_InvalidEndpoint(t *testing.T) {
	_, err := buildProviderAuthorizeURL("://not-a-url", "client-1", "http://127.0.0.1:1234/callback", "state-1", "challenge-1", nil)
	assert.Error(t, err)
}

func TestExchangeCodeForToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.NoError(t, r.ParseForm())
			assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
			assert.Equal(t, "the-code", r.FormValue("code"))
			assert.Equal(t, "client-1", r.FormValue("client_id"))
			assert.Equal(t, "verifier-1", r.FormValue("code_verifier"))

			_, _ = w.Write([]byte(`{
				"access_token": "access-1",
				"refresh_token": "refresh-1",
				"id_token": "id-1",
				"token_type": "Bearer",
				"expires_in": 3600
			}`))
		}))
		defer srv.Close()

		out, err := exchangeCodeForToken(context.Background(), srv.URL, tokenExchangeInput{
			Code:         "the-code",
			ClientID:     "client-1",
			RedirectURI:  "http://127.0.0.1:1234/callback",
			CodeVerifier: "verifier-1",
		})
		assert.NoError(t, err)
		if assert.NotNil(t, out) {
			assert.Equal(t, "access-1", out.AccessToken)
			assert.Equal(t, "refresh-1", out.RefreshToken)
			assert.Equal(t, 3600, out.ExpiresIn)
		}
	})

	t.Run("oauth error response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code expired"}`))
		}))
		defer srv.Close()

		_, err := exchangeCodeForToken(context.Background(), srv.URL, tokenExchangeInput{Code: "x"})
		assert.ErrorContains(t, err, "invalid_grant")
		assert.ErrorContains(t, err, "code expired")
	})

	t.Run("non-200 without error body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{}`))
		}))
		defer srv.Close()

		_, err := exchangeCodeForToken(context.Background(), srv.URL, tokenExchangeInput{Code: "x"})
		assert.ErrorContains(t, err, "500")
	})

	t.Run("empty access token", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
		}))
		defer srv.Close()

		_, err := exchangeCodeForToken(context.Background(), srv.URL, tokenExchangeInput{Code: "x"})
		assert.ErrorContains(t, err, "empty access_token")
	})
}

func TestProviderCallbackHandler(t *testing.T) {
	t.Run("successful callback", func(t *testing.T) {
		result := make(chan providerCallbackResult, 1)
		h := newProviderCallbackHandler("expected-state", result)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/callback?code=the-code&state=expected-state", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		r := <-result
		assert.Equal(t, "the-code", r.code)
		assert.NoError(t, r.err)
	})

	t.Run("state mismatch", func(t *testing.T) {
		result := make(chan providerCallbackResult, 1)
		h := newProviderCallbackHandler("expected-state", result)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/callback?code=the-code&state=wrong-state", nil)
		h.ServeHTTP(rec, req)

		r := <-result
		assert.ErrorContains(t, r.err, "state parameter mismatch")
	})

	t.Run("missing code", func(t *testing.T) {
		result := make(chan providerCallbackResult, 1)
		h := newProviderCallbackHandler("expected-state", result)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/callback?state=expected-state", nil)
		h.ServeHTTP(rec, req)

		r := <-result
		assert.ErrorContains(t, r.err, "no authorization code")
	})

	t.Run("provider returned error", func(t *testing.T) {
		result := make(chan providerCallbackResult, 1)
		h := newProviderCallbackHandler("expected-state", result)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=user+said+no", nil)
		h.ServeHTTP(rec, req)

		r := <-result
		assert.ErrorContains(t, r.err, "access_denied")
		assert.ErrorContains(t, r.err, "user said no")
	})

	t.Run("second request after handled is rejected", func(t *testing.T) {
		result := make(chan providerCallbackResult, 1)
		h := newProviderCallbackHandler("expected-state", result)

		req1 := httptest.NewRequest(http.MethodGet, "/callback?code=the-code&state=expected-state", nil)
		h.ServeHTTP(httptest.NewRecorder(), req1)
		<-result

		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodGet, "/callback?code=another-code&state=expected-state", nil)
		h.ServeHTTP(rec2, req2)

		assert.Equal(t, http.StatusConflict, rec2.Code)
	})

	t.Run("rejects non-GET", func(t *testing.T) {
		result := make(chan providerCallbackResult, 1)
		h := newProviderCallbackHandler("expected-state", result)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/callback", nil)
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})
}
