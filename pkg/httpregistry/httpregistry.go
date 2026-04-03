package httpregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/awsconfigfile"
	"github.com/fwdcloudsec/granted/pkg/idclogin"
	"github.com/fwdcloudsec/granted/pkg/providercfg"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"gopkg.in/ini.v1"
)

type Registry struct {
	opts         Opts
	mu           sync.Mutex
	cfg          *providercfg.ProviderConfig
	tokenStorage securestorage.ProviderTokenStorage
}

type Opts struct {
	Name     string
	URL      string
	TenantID string
}

// getConfig lazily loads the provider configuration.
// This avoids slowing down Granted startup when the registry isn't needed.
func (r *Registry) getConfig(interactive bool) (*providercfg.ProviderConfig, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cfg != nil {
		return r.cfg, nil
	}

	cfg, err := providercfg.LoadFromURL(context.Background(), r.opts.URL)
	if err != nil {
		if interactive {
			clio.Warnf("Failed to load provider config from %s: %s", r.opts.URL, err)
		}
		return nil, err
	}

	r.cfg = cfg
	return r.cfg, nil
}

// getToken returns a valid Bearer token for the provider, triggering login if interactive.
func (r *Registry) getToken(ctx context.Context, cfg *providercfg.ProviderConfig, interactive bool) (string, error) {
	if cfg.Auth.Type != "oidc" {
		return "", nil
	}

	token := r.tokenStorage.GetValidToken(r.opts.URL)
	if token != nil {
		return token.AccessToken, nil
	}

	if !interactive {
		return "", fmt.Errorf("no valid token for provider %s. Run 'granted auth login --url %s' to authenticate", r.opts.URL, r.opts.URL)
	}

	output, err := idclogin.ProviderLogin(ctx, idclogin.ProviderLoginInput{
		IssuerURL: cfg.Auth.Issuer,
		ClientID:  cfg.Auth.ClientID,
		Scopes:    cfg.Auth.Scopes,
	})
	if err != nil {
		return "", err
	}

	providerToken := securestorage.ProviderToken{
		AccessToken:  output.AccessToken,
		RefreshToken: output.RefreshToken,
		IDToken:      output.IDToken,
		TokenType:    output.TokenType,
		Expiry:       time.Now().Add(time.Duration(output.ExpiresIn) * time.Second),
		ProviderURL:  r.opts.URL,
		TenantID:     r.opts.TenantID,
	}

	if err := r.tokenStorage.StoreToken(r.opts.URL, providerToken); err != nil {
		clio.Warnf("failed to store provider token: %s", err)
	}

	return output.AccessToken, nil
}

func New(opts Opts) *Registry {
	return &Registry{
		opts:         opts,
		tokenStorage: securestorage.NewProviderTokenStorage(),
	}
}

type listProfilesResponse struct {
	Profiles      []profileEntry `json:"profiles"`
	NextPageToken string         `json:"next_page_token"`
}

type profileEntry struct {
	Name       string          `json:"name"`
	Attributes []profileKeyVal `json:"attributes"`
}

type profileKeyVal struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// fetchProfiles retrieves raw profile entries from the HTTP registry API.
func (r *Registry) fetchProfiles(ctx context.Context, interactive bool) ([]profileEntry, error) {
	cfg, err := r.getConfig(interactive)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 30 * time.Second}

	accessToken, err := r.getToken(ctx, cfg, interactive)
	if err != nil {
		return nil, err
	}

	var allProfiles []profileEntry
	var pageToken string

	for {
		listURL := fmt.Sprintf("%s/v1/registry/profiles", cfg.APIURL)
		if pageToken != "" {
			listURL += "?page_token=" + pageToken
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")

		if accessToken != "" {
			req.Header.Set("Authorization", "Bearer "+accessToken)
		}
		tenantID := r.opts.TenantID
		if tenantID == "" {
			tenantID = cfg.TenantID
		}
		if tenantID != "" {
			req.Header.Set("X-Tenant-ID", tenantID)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetching profiles from %s: %w", listURL, err)
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("profile registry returned HTTP %d from %s", resp.StatusCode, listURL)
		}

		var listResp listProfilesResponse
		if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("decoding profile list from %s: %w", listURL, err)
		}
		_ = resp.Body.Close()

		allProfiles = append(allProfiles, listResp.Profiles...)

		if listResp.NextPageToken == "" {
			break
		}
		pageToken = listResp.NextPageToken
	}

	return allProfiles, nil
}

func (r *Registry) AWSProfiles(ctx context.Context, interactive bool) (*ini.File, error) {
	allProfiles, err := r.fetchProfiles(ctx, interactive)
	if err != nil {
		return nil, err
	}

	result := ini.Empty()

	for _, profile := range allProfiles {
		section, err := result.NewSection(profile.Name)
		if err != nil {
			return nil, err
		}

		for _, attr := range profile.Attributes {
			_, err := section.NewKey(attr.Key, attr.Value)
			if err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

// GetProfiles implements awsconfigfile.Source, allowing an HTTP registry
// to be used as a profile source in `granted sso generate` and `granted sso populate`.
func (r *Registry) GetProfiles(ctx context.Context) ([]awsconfigfile.SSOProfile, error) {
	entries, err := r.fetchProfiles(ctx, true)
	if err != nil {
		return nil, err
	}

	var profiles []awsconfigfile.SSOProfile
	for _, entry := range entries {
		attrs := make(map[string]string, len(entry.Attributes))
		for _, kv := range entry.Attributes {
			attrs[kv.Key] = kv.Value
		}

		profiles = append(profiles, awsconfigfile.SSOProfile{
			SSOStartURL:   attrs["sso_start_url"],
			SSORegion:     attrs["sso_region"],
			AccountID:     attrs["sso_account_id"],
			AccountName:   attrs["account_name"],
			RoleName:      attrs["sso_role_name"],
			GeneratedFrom: r.opts.Name,
		})
	}

	return profiles, nil
}
