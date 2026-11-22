package httpprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fwdcloudsec/granted/pkg/hook/accessrequesthook"
	"github.com/fwdcloudsec/granted/pkg/providercfg"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/stretchr/testify/assert"
)

// fakeTokenBackend is an in-memory securestorage backend so tests never
// touch the real OS keyring.
type fakeTokenBackend struct {
	data map[string][]byte
}

func (f *fakeTokenBackend) Retrieve(key string, target interface{}) error {
	b, ok := f.data[key]
	if !ok {
		return errors.New("not found")
	}
	return json.Unmarshal(b, target)
}

func (f *fakeTokenBackend) Store(key string, payload interface{}) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if f.data == nil {
		f.data = map[string][]byte{}
	}
	f.data[key] = b
	return nil
}

func (f *fakeTokenBackend) Clear(key string) error {
	delete(f.data, key)
	return nil
}

func newTestProvider(t *testing.T, apiURL string) (*HTTPProvider, *fakeTokenBackend) {
	t.Helper()
	backend := &fakeTokenBackend{}
	p := New(&providercfg.ProviderConfig{APIURL: apiURL, Auth: providercfg.AuthConfig{Type: "oidc"}}, "https://provider.example.com", "")
	p.tokenStorage = securestorage.ProviderTokenStorage{SecureStorage: backend}
	return p, backend
}

func storeValidToken(t *testing.T, p *HTTPProvider, token string) {
	t.Helper()
	err := p.tokenStorage.StoreToken(p.providerURL, securestorage.ProviderToken{
		AccessToken: token,
		Expiry:      time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)
}

func TestNew(t *testing.T) {
	t.Run("uses explicit tenant id", func(t *testing.T) {
		p := New(&providercfg.ProviderConfig{TenantID: "from-config"}, "https://provider.example.com", "explicit-tenant")
		assert.Equal(t, "explicit-tenant", p.tenantID)
	})

	t.Run("falls back to config tenant id", func(t *testing.T) {
		p := New(&providercfg.ProviderConfig{TenantID: "from-config"}, "https://provider.example.com", "")
		assert.Equal(t, "from-config", p.tenantID)
	})
}

func TestHTTPProvider_Ensure(t *testing.T) {
	t.Run("success with valid token", func(t *testing.T) {
		var gotAuth, gotTenant string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v1/access/ensure", r.URL.Path)
			gotAuth = r.Header.Get("Authorization")
			gotTenant = r.Header.Get("X-Tenant-ID")
			_, _ = w.Write([]byte(`{"grants":[{"id":"g1","name":"n1","status":"active","change":"none","duration":"1h0m0s"}]}`))
		}))
		defer srv.Close()

		p, _ := newTestProvider(t, srv.URL)
		p.tenantID = "tenant-1"
		storeValidToken(t, p, "a-token")

		res, err := p.Ensure(context.Background(), &accessrequesthook.EnsureRequest{})
		assert.NoError(t, err)
		assert.Equal(t, "Bearer a-token", gotAuth)
		assert.Equal(t, "tenant-1", gotTenant)
		if assert.Len(t, res.Grants, 1) {
			assert.Equal(t, "g1", res.Grants[0].ID)
			assert.Equal(t, accessrequesthook.GrantStatusActive, res.Grants[0].Status)
			assert.Equal(t, time.Hour, res.Grants[0].Duration)
		}
	})

	t.Run("getToken with no stored token and non-interactive returns helpful error", func(t *testing.T) {
		p, _ := newTestProvider(t, "https://unused.example.com")
		_, err := p.getToken(context.Background(), false)
		assert.ErrorContains(t, err, "granted auth login")
	})

	t.Run("no stored token triggers an interactive login attempt", func(t *testing.T) {
		// Ensure always calls getToken with interactive=true, so with no
		// stored token it attempts a real login rather than returning the
		// "run granted auth login" hint.
		p, _ := newTestProvider(t, "https://unused.example.com")
		_, err := p.Ensure(context.Background(), &accessrequesthook.EnsureRequest{})
		assert.ErrorContains(t, err, "getting auth token")
		assert.NotContains(t, err.Error(), "granted auth login")
	})

	t.Run("non-200 response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		p, _ := newTestProvider(t, srv.URL)
		storeValidToken(t, p, "a-token")

		_, err := p.Ensure(context.Background(), &accessrequesthook.EnsureRequest{})
		assert.ErrorContains(t, err, "500")
	})

	t.Run("401 with no stored token to retry returns UnauthorizedError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		p, _ := newTestProvider(t, srv.URL)
		p.cfg.Auth.Type = "" // Login() will fail fast since auth type isn't oidc
		storeValidToken(t, p, "stale-token")

		_, err := p.Ensure(context.Background(), &accessrequesthook.EnsureRequest{})
		assert.ErrorContains(t, err, "re-authentication failed")
	})
}

func TestHTTPProvider_Login(t *testing.T) {
	t.Run("rejects non-oidc auth type", func(t *testing.T) {
		p := New(&providercfg.ProviderConfig{Auth: providercfg.AuthConfig{Type: "saml"}}, "https://provider.example.com", "")
		err := p.Login(context.Background())
		assert.ErrorContains(t, err, "unsupported auth type")
	})
}

func TestHTTPProvider_RequestURL(t *testing.T) {
	t.Run("joins access url and request id", func(t *testing.T) {
		p := New(&providercfg.ProviderConfig{AccessURL: "https://access.example.com"}, "https://provider.example.com", "")
		assert.Equal(t, "https://access.example.com/access/requests/req-1", p.RequestURL("req-1"))
	})

	t.Run("falls back to string concatenation on unparsable access url", func(t *testing.T) {
		p := New(&providercfg.ProviderConfig{AccessURL: "://not-a-url"}, "https://provider.example.com", "")
		got := p.RequestURL("req-1")
		assert.Contains(t, got, "req-1")
	})
}

func TestUnauthorizedError(t *testing.T) {
	err := &UnauthorizedError{StatusCode: 401}
	assert.Equal(t, "unauthorized (HTTP 401): token expired or invalid", err.Error())
	assert.True(t, err.IsUnauthorized())
	assert.True(t, IsUnauthorized(err))
	assert.False(t, IsUnauthorized(errors.New("some other error")))
}

func TestToAPIRequest(t *testing.T) {
	d := 2 * time.Hour
	req := &accessrequesthook.EnsureRequest{
		DryRun: true,
		Entitlements: []accessrequesthook.EntitlementInput{
			{Target: "t1", Role: "r1", Duration: &d},
			{Target: "t2", Role: "r2"},
		},
		Justification: accessrequesthook.Justification{Reason: "because", Attachments: []string{"a1"}},
	}

	got := toAPIRequest(req)
	assert.True(t, got.DryRun)
	assert.Equal(t, "because", got.Justification.Reason)
	assert.Equal(t, []string{"a1"}, got.Justification.Attachments)
	if assert.Len(t, got.Entitlements, 2) {
		assert.Equal(t, "t1", got.Entitlements[0].Target)
		assert.Equal(t, "2h0m0s", got.Entitlements[0].Duration)
		assert.Equal(t, "", got.Entitlements[1].Duration)
	}
}

func TestFromAPIResponse(t *testing.T) {
	expiresAt := "2026-01-01T00:00:00Z"
	activatedAt := "2026-01-02T00:00:00Z"

	resp := &apiEnsureResponse{
		Validation: &apiValidation{HasReason: true, HasJiraTicket: true},
		Diagnostics: []apiDiagnostic{
			{Level: "warning", Message: "careful"},
		},
		Grants: []apiGrantResult{
			{
				ID: "g1", Name: "n1", Status: "active", Change: "activated", Approved: true,
				Duration: "1h30m0s", ExpiresAt: &expiresAt, ActivatedAt: &activatedAt,
				AccessRequestID: "req-1", ProvisioningStatus: "successful",
				Extension: &apiExtension{ExtensionDuration: "30m0s"},
			},
			{
				// malformed duration/timestamps should be left as zero values, not error
				ID: "g2", Duration: "not-a-duration", ExpiresAt: strPtr("not-a-time"),
			},
		},
	}

	got := fromAPIResponse(resp)
	assert.True(t, got.Validation.HasReason)
	assert.True(t, got.Validation.HasJiraTicket)
	if assert.Len(t, got.Diagnostics, 1) {
		assert.Equal(t, "careful", got.Diagnostics[0].Message)
	}
	if assert.Len(t, got.Grants, 2) {
		g1 := got.Grants[0]
		assert.Equal(t, accessrequesthook.GrantStatus("active"), g1.Status)
		assert.Equal(t, accessrequesthook.GrantChange("activated"), g1.Change)
		assert.Equal(t, 90*time.Minute, g1.Duration)
		assert.NotNil(t, g1.ExpiresAt)
		assert.NotNil(t, g1.ActivatedAt)
		if assert.NotNil(t, g1.Extension) {
			assert.Equal(t, 30*time.Minute, g1.Extension.ExtensionDuration)
		}

		g2 := got.Grants[1]
		assert.Equal(t, time.Duration(0), g2.Duration)
		assert.Nil(t, g2.ExpiresAt)
	}
}

func strPtr(s string) *string { return &s }
