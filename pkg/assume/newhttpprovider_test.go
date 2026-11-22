package assume

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fwdcloudsec/granted/pkg/hook/httpprovider"
	"github.com/stretchr/testify/assert"
)

func TestNewHTTPProvider(t *testing.T) {
	t.Run("builds a provider from a valid provider config", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/granted/config.json", r.URL.Path)
			_, _ = w.Write([]byte(`{"provider":"example","api_url":"https://api.example.com"}`))
		}))
		defer srv.Close()

		provider, err := newHTTPProvider(srv.URL)
		assert.NoError(t, err)
		if assert.NotNil(t, provider) {
			_, ok := provider.(*httpprovider.HTTPProvider)
			assert.True(t, ok, "expected an *httpprovider.HTTPProvider")
		}
	})

	t.Run("propagates provider config load errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		provider, err := newHTTPProvider(srv.URL)
		assert.Nil(t, provider)
		assert.Error(t, err)
	})
}
