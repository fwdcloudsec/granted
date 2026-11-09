package httpregistry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func (f *fakeTokenBackend) Clear(key string) error { delete(f.data, key); return nil }

// testServer wires up a fake provider config endpoint and a fake registry
// profiles endpoint (with optional pagination), returning the server and
// the configured provider API base URL for AWSProfiles/GetProfiles calls.
func testServer(t *testing.T, pages [][]profileEntry, authType string) *httptest.Server {
	t.Helper()
	var mux http.ServeMux
	var apiURL string

	mux.HandleFunc("/granted/config.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(providercfg.ProviderConfig{
			Provider: "example",
			APIURL:   apiURL,
			Auth:     providercfg.AuthConfig{Type: authType},
		})
	})

	mux.HandleFunc("/v1/registry/profiles", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("page_token")
		idx := 0
		if token != "" {
			var err error
			idx, err = parsePageToken(token)
			assert.NoError(t, err)
		}

		resp := listProfilesResponse{Profiles: pages[idx]}
		if idx+1 < len(pages) {
			resp.NextPageToken = pageToken(idx + 1)
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(&mux)
	apiURL = srv.URL
	return srv
}

func pageToken(i int) string {
	return []string{"page-0", "page-1", "page-2"}[i]
}

func parsePageToken(tok string) (int, error) {
	switch tok {
	case "page-0":
		return 0, nil
	case "page-1":
		return 1, nil
	case "page-2":
		return 2, nil
	}
	return 0, errors.New("unknown page token: " + tok)
}

func newRegistryWithToken(opts Opts, token string) *Registry {
	r := New(opts)
	if token != "" {
		r.tokenStorage = securestorage.ProviderTokenStorage{SecureStorage: &fakeTokenBackend{}}
		_ = r.tokenStorage.StoreToken(opts.URL, securestorage.ProviderToken{
			AccessToken: token,
			Expiry:      time.Now().Add(time.Hour),
		})
	}
	return r
}

func TestRegistry_AWSProfiles(t *testing.T) {
	entries := []profileEntry{
		{Name: "profile account-a/role-a", Attributes: []profileKeyVal{
			{Key: "sso_start_url", Value: "https://start.example.com"},
			{Key: "sso_account_id", Value: "111111111111"},
		}},
	}
	srv := testServer(t, [][]profileEntry{entries}, "")
	defer srv.Close()

	r := New(Opts{Name: "my-registry", URL: srv.URL})
	f, err := r.AWSProfiles(context.Background(), false)
	assert.NoError(t, err)

	sec := f.Section("profile account-a/role-a")
	assert.Equal(t, "https://start.example.com", sec.Key("sso_start_url").Value())
	assert.Equal(t, "111111111111", sec.Key("sso_account_id").Value())
}

func TestRegistry_AWSProfiles_Pagination(t *testing.T) {
	page0 := []profileEntry{{Name: "profile p0"}}
	page1 := []profileEntry{{Name: "profile p1"}}
	page2 := []profileEntry{{Name: "profile p2"}}
	srv := testServer(t, [][]profileEntry{page0, page1, page2}, "")
	defer srv.Close()

	r := New(Opts{Name: "my-registry", URL: srv.URL})
	f, err := r.AWSProfiles(context.Background(), false)
	assert.NoError(t, err)

	for _, name := range []string{"profile p0", "profile p1", "profile p2"} {
		assert.True(t, f.HasSection(name), "missing section %s", name)
	}
}

func TestRegistry_GetProfiles(t *testing.T) {
	entries := []profileEntry{
		{Name: "profile a", Attributes: []profileKeyVal{
			{Key: "sso_start_url", Value: "https://start.example.com"},
			{Key: "sso_region", Value: "us-east-1"},
			{Key: "sso_account_id", Value: "111111111111"},
			{Key: "account_name", Value: "my-account"},
			{Key: "sso_role_name", Value: "Admin"},
		}},
	}
	srv := testServer(t, [][]profileEntry{entries}, "")
	defer srv.Close()

	r := New(Opts{Name: "my-registry", URL: srv.URL})
	profiles, err := r.GetProfiles(context.Background())
	assert.NoError(t, err)
	if assert.Len(t, profiles, 1) {
		p := profiles[0]
		assert.Equal(t, "https://start.example.com", p.SSOStartURL)
		assert.Equal(t, "us-east-1", p.SSORegion)
		assert.Equal(t, "111111111111", p.AccountID)
		assert.Equal(t, "my-account", p.AccountName)
		assert.Equal(t, "Admin", p.RoleName)
		assert.Equal(t, "my-registry", p.GeneratedFrom)
	}
}

func TestRegistry_FetchProfiles_SendsAuthAndTenantHeaders(t *testing.T) {
	var gotAuth, gotTenant string
	var mux http.ServeMux
	var apiURL string

	mux.HandleFunc("/granted/config.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(providercfg.ProviderConfig{APIURL: apiURL, Auth: providercfg.AuthConfig{Type: "oidc"}})
	})
	mux.HandleFunc("/v1/registry/profiles", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotTenant = r.Header.Get("X-Tenant-ID")
		_ = json.NewEncoder(w).Encode(listProfilesResponse{})
	})
	srv := httptest.NewServer(&mux)
	defer srv.Close()
	apiURL = srv.URL

	r := newRegistryWithToken(Opts{Name: "my-registry", URL: srv.URL, TenantID: "tenant-1"}, "a-token")
	_, err := r.fetchProfiles(context.Background(), false)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer a-token", gotAuth)
	assert.Equal(t, "tenant-1", gotTenant)
}

func TestRegistry_FetchProfiles_TenantFallsBackToProviderConfig(t *testing.T) {
	var gotTenant string
	var mux http.ServeMux
	var apiURL string

	mux.HandleFunc("/granted/config.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(providercfg.ProviderConfig{APIURL: apiURL, TenantID: "from-provider-config"})
	})
	mux.HandleFunc("/v1/registry/profiles", func(w http.ResponseWriter, r *http.Request) {
		gotTenant = r.Header.Get("X-Tenant-ID")
		_ = json.NewEncoder(w).Encode(listProfilesResponse{})
	})
	srv := httptest.NewServer(&mux)
	defer srv.Close()
	apiURL = srv.URL

	r := New(Opts{Name: "my-registry", URL: srv.URL}) // no TenantID set on opts
	_, err := r.fetchProfiles(context.Background(), false)
	assert.NoError(t, err)
	assert.Equal(t, "from-provider-config", gotTenant)
}

func TestRegistry_GetConfig_Caching(t *testing.T) {
	calls := 0
	var mux http.ServeMux
	mux.HandleFunc("/granted/config.json", func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(providercfg.ProviderConfig{})
	})
	srv := httptest.NewServer(&mux)
	defer srv.Close()

	r := New(Opts{Name: "my-registry", URL: srv.URL})
	_, err := r.getConfig(false)
	assert.NoError(t, err)
	_, err = r.getConfig(false)
	assert.NoError(t, err)

	assert.Equal(t, 1, calls)
}

func TestRegistry_GetConfig_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := New(Opts{Name: "my-registry", URL: srv.URL})
	_, err := r.getConfig(false)
	assert.Error(t, err)
}

func TestRegistry_GetToken_NonOIDCProviderReturnsEmptyToken(t *testing.T) {
	r := New(Opts{Name: "my-registry", URL: "https://unused.example.com"})
	token, err := r.getToken(context.Background(), &providercfg.ProviderConfig{Auth: providercfg.AuthConfig{Type: "none"}}, false)
	assert.NoError(t, err)
	assert.Equal(t, "", token)
}

func TestRegistry_GetToken_NoStoredTokenNonInteractiveReturnsHelpfulError(t *testing.T) {
	r := New(Opts{Name: "my-registry", URL: "https://provider.example.com"})
	_, err := r.getToken(context.Background(), &providercfg.ProviderConfig{Auth: providercfg.AuthConfig{Type: "oidc"}}, false)
	assert.ErrorContains(t, err, "granted auth login")
}

func TestRegistry_GetToken_UsesStoredValidToken(t *testing.T) {
	r := newRegistryWithToken(Opts{Name: "my-registry", URL: "https://provider.example.com"}, "stored-token")
	token, err := r.getToken(context.Background(), &providercfg.ProviderConfig{Auth: providercfg.AuthConfig{Type: "oidc"}}, false)
	assert.NoError(t, err)
	assert.Equal(t, "stored-token", token)
}

func TestRegistry_FetchProfiles_NonOKStatus(t *testing.T) {
	var mux http.ServeMux
	var apiURL string
	mux.HandleFunc("/granted/config.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(providercfg.ProviderConfig{APIURL: apiURL})
	})
	mux.HandleFunc("/v1/registry/profiles", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(&mux)
	defer srv.Close()
	apiURL = srv.URL

	r := New(Opts{Name: "my-registry", URL: srv.URL})
	_, err := r.fetchProfiles(context.Background(), false)
	assert.ErrorContains(t, err, "403")
}
