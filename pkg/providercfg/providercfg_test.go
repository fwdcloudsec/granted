package providercfg

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/stretchr/testify/assert"
	"gopkg.in/ini.v1"
)

func TestLoadFromURL(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/granted/config.json", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"provider": "example",
				"version": "1.0.0",
				"api_url": "https://api.example.com",
				"access_url": "https://access.example.com",
				"tenant_id": "tenant-1",
				"auth": {"type": "oidc", "issuer": "https://issuer.example.com", "client_id": "abc", "scopes": ["openid"]}
			}`))
		}))
		defer srv.Close()

		cfg, err := LoadFromURL(context.Background(), srv.URL)
		assert.NoError(t, err)
		if assert.NotNil(t, cfg) {
			assert.Equal(t, "example", cfg.Provider)
			assert.Equal(t, "https://api.example.com", cfg.APIURL)
			assert.Equal(t, "tenant-1", cfg.TenantID)
			assert.Equal(t, "oidc", cfg.Auth.Type)
			assert.Equal(t, []string{"openid"}, cfg.Auth.Scopes)
		}
	})

	t.Run("non-200 status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		cfg, err := LoadFromURL(context.Background(), srv.URL)
		assert.Nil(t, cfg)
		assert.ErrorContains(t, err, "404")
	})

	t.Run("invalid json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		defer srv.Close()

		cfg, err := LoadFromURL(context.Background(), srv.URL)
		assert.Nil(t, cfg)
		assert.Error(t, err)
	})

	t.Run("invalid provider url", func(t *testing.T) {
		cfg, err := LoadFromURL(context.Background(), "://not-a-url")
		assert.Nil(t, cfg)
		assert.ErrorContains(t, err, "invalid provider URL")
	})
}

func newProfileWithKeys(t *testing.T, keys map[string]string) *cfaws.Profile {
	t.Helper()

	f := ini.Empty()
	sec, err := f.NewSection("profile test")
	assert.NoError(t, err)
	for k, v := range keys {
		_, err := sec.NewKey(k, v)
		assert.NoError(t, err)
	}

	return &cfaws.Profile{Name: "test", RawConfig: sec}
}

func TestGetProviderURL(t *testing.T) {
	t.Run("nil profile", func(t *testing.T) {
		assert.Equal(t, "", GetProviderURL(nil))
	})

	t.Run("nil raw config", func(t *testing.T) {
		assert.Equal(t, "", GetProviderURL(&cfaws.Profile{Name: "test"}))
	})

	t.Run("no provider url set", func(t *testing.T) {
		p := newProfileWithKeys(t, map[string]string{"region": "us-east-1"})
		assert.Equal(t, "", GetProviderURL(p))
	})

	t.Run("granted_access_provider_url takes precedence", func(t *testing.T) {
		p := newProfileWithKeys(t, map[string]string{
			"granted_access_provider_url": "https://new.example.com",
			"common_fate_url":             "https://legacy.example.com",
		})
		assert.Equal(t, "https://new.example.com", GetProviderURL(p))
	})

	t.Run("falls back to legacy common_fate_url", func(t *testing.T) {
		p := newProfileWithKeys(t, map[string]string{
			"common_fate_url": "https://legacy.example.com",
		})
		assert.Equal(t, "https://legacy.example.com", GetProviderURL(p))
	})

	t.Run("empty granted_access_provider_url falls back to legacy", func(t *testing.T) {
		p := newProfileWithKeys(t, map[string]string{
			"granted_access_provider_url": "",
			"common_fate_url":             "https://legacy.example.com",
		})
		assert.Equal(t, "https://legacy.example.com", GetProviderURL(p))
	})
}

func TestGenerateRequestURL(t *testing.T) {
	tests := []struct {
		name      string
		accessURL string
		requestID string
		want      string
		wantErr   bool
	}{
		{
			name:      "simple",
			accessURL: "https://access.example.com",
			requestID: "req-123",
			want:      "https://access.example.com/access/requests/req-123",
		},
		{
			name:      "trailing slash on access url",
			accessURL: "https://access.example.com/",
			requestID: "req-123",
			want:      "https://access.example.com/access/requests/req-123",
		},
		{
			name:      "invalid url",
			accessURL: "://not-a-url",
			requestID: "req-123",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateRequestURL(tt.accessURL, tt.requestID)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
