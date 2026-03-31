package httpregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/providercfg"
	"gopkg.in/ini.v1"
)

type Registry struct {
	opts Opts
	mu   sync.Mutex
	cfg  *providercfg.ProviderConfig
}

type Opts struct {
	Name string
	URL  string
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

func New(opts Opts) *Registry {
	return &Registry{opts: opts}
}

type listProfilesResponse struct {
	Profiles      []profileEntry `json:"profiles"`
	NextPageToken string         `json:"next_page_token"`
}

type profileEntry struct {
	Name       string           `json:"name"`
	Attributes []profileKeyVal  `json:"attributes"`
}

type profileKeyVal struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (r *Registry) AWSProfiles(ctx context.Context, interactive bool) (*ini.File, error) {
	cfg, err := r.getConfig(interactive)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 30 * time.Second}

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

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetching profiles from %s: %w", listURL, err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("profile registry returned HTTP %d from %s", resp.StatusCode, listURL)
		}

		var listResp listProfilesResponse
		if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decoding profile list from %s: %w", listURL, err)
		}
		resp.Body.Close()

		allProfiles = append(allProfiles, listResp.Profiles...)

		if listResp.NextPageToken == "" {
			break
		}
		pageToken = listResp.NextPageToken
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
