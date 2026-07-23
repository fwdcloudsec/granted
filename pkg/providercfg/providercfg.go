package providercfg

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
)

type ProviderConfig struct {
	Provider  string     `json:"provider"`
	Version   string     `json:"version"`
	APIURL    string     `json:"api_url"`
	AccessURL string     `json:"access_url"`
	TenantID  string     `json:"tenant_id,omitempty"`
	Auth      AuthConfig `json:"auth"`
}

type AuthConfig struct {
	Type     string   `json:"type"`
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// LoadFromURL fetches the provider configuration from {providerURL}/granted/config.json.
func LoadFromURL(ctx context.Context, providerURL string) (*ProviderConfig, error) {
	u, err := url.Parse(providerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid provider URL (%s): %w", providerURL, err)
	}

	configURL := u.JoinPath("granted", "config.json").String()
	clio.Debugw("loading provider config", "url", configURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching provider config from %s: %w", configURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider config returned HTTP %d from %s", resp.StatusCode, configURL)
	}

	var cfg ProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decoding provider config from %s: %w", configURL, err)
	}

	return &cfg, nil
}

// GetProviderURL reads the access provider URL from a profile's raw config.
// It checks granted_access_provider_url first, then common_fate_url as a legacy alias.
// Returns an empty string if neither key is set.
func GetProviderURL(profile *cfaws.Profile) string {
	if profile == nil || profile.RawConfig == nil {
		return ""
	}

	for _, key := range []string{"granted_access_provider_url", "common_fate_url"} {
		if profile.RawConfig.HasKey(key) {
			k, err := profile.RawConfig.GetKey(key)
			if err != nil {
				clio.Debugw("error reading profile key", "key", key, "error", err)
				continue
			}
			if k.Value() != "" {
				return k.Value()
			}
		}
	}

	return ""
}

// GenerateRequestURL builds a URL to view an access request in the provider UI.
func GenerateRequestURL(accessURL string, requestID string) (string, error) {
	u, err := url.Parse(accessURL)
	if err != nil {
		return "", err
	}
	p := u.JoinPath("access", "requests", requestID)
	return p.String(), nil
}
