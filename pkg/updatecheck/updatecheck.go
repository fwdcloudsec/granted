// Package updatecheck checks GitHub Releases for newer versions of granted,
// replacing the old common-fate/updatecheck client which pointed at a
// Common Fate hosted service that this fork no longer has access to.
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/common-fate/clio"
	"golang.org/x/mod/semver"

	grantedconfig "github.com/fwdcloudsec/granted/pkg/config"
)

const (
	releasesURL    = "https://github.com/fwdcloudsec/granted/releases/latest"
	checkInterval  = 24 * time.Hour
	requestTimeout = 3 * time.Second
	cacheFileName  = "update-check.json"
)

// latestReleaseURL is a var (not a const) so tests can point it at a local
// server instead of the real GitHub API.
var latestReleaseURL = "https://api.github.com/repos/fwdcloudsec/granted/releases/latest"

var (
	wg      sync.WaitGroup
	mu      sync.Mutex
	message string
)

type cacheState struct {
	LastChecked time.Time `json:"last_checked"`
}

type release struct {
	TagName string `json:"tag_name"`
}

// Check asynchronously checks GitHub Releases for a newer version of granted.
// Call Print() afterwards to display any message that was found.
func Check(currentVersion string, prod bool) {
	if !prod {
		return
	}
	if os.Getenv("GRANTED_DISABLE_UPDATE_CHECK") == "true" {
		clio.Debug("GRANTED_DISABLE_UPDATE_CHECK env var is true, skipping update check")
		return
	}
	if !dueForCheck() {
		return
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		msg, err := checkLatestRelease(currentVersion)
		if err != nil {
			clio.Debugf("error checking for updates: %s", err)
			return
		}

		mu.Lock()
		message = msg
		mu.Unlock()

		if err := saveLastChecked(); err != nil {
			clio.Debugf("error saving update check cache: %s", err)
		}
	}()
}

// Print displays any update message found by Check. It blocks until Check
// has finished, so it should be called with defer immediately after Check.
func Print() {
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if message != "" {
		clio.Info(message)
	}
}

func checkLatestRelease(currentVersion string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestReleaseURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Accept", "application/vnd.github+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status from GitHub releases API: %d", res.StatusCode)
	}

	var r release
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		return "", err
	}

	latest := "v" + strings.TrimPrefix(r.TagName, "v")
	current := "v" + strings.TrimPrefix(currentVersion, "v")

	if !semver.IsValid(latest) || !semver.IsValid(current) {
		return "", nil
	}

	if semver.Compare(latest, current) > 0 {
		return fmt.Sprintf("A new version of granted is available: %s (you have %s). Download it from %s", r.TagName, currentVersion, releasesURL), nil
	}

	return "", nil
}

func cacheFilePath() (string, error) {
	dir, err := grantedconfig.GrantedCacheFolder()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, cacheFileName), nil
}

func dueForCheck() bool {
	path, err := cacheFilePath()
	if err != nil {
		return true
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return true
	}

	var s cacheState
	if err := json.Unmarshal(b, &s); err != nil {
		return true
	}

	return time.Since(s.LastChecked) > checkInterval
}

func saveLastChecked() error {
	dir, err := grantedconfig.GrantedCacheFolder()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	path, err := cacheFilePath()
	if err != nil {
		return err
	}

	b, err := json.Marshal(cacheState{LastChecked: time.Now()})
	if err != nil {
		return err
	}

	return os.WriteFile(path, b, 0600)
}
