package updatecheck

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func withTempGrantedHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // windows
}

func withFakeReleaseServer(t *testing.T, tagName string, status int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(`{"tag_name":"` + tagName + `"}`))
	}))
	t.Cleanup(srv.Close)

	old := latestReleaseURL
	latestReleaseURL = srv.URL
	t.Cleanup(func() { latestReleaseURL = old })
}

func TestCheckLatestRelease(t *testing.T) {
	tests := []struct {
		name           string
		latestTag      string
		currentVersion string
		wantMessage    bool
	}{
		{"newer version available", "v2.0.0", "v1.0.0", true},
		{"newer version available without v prefix on current", "v2.0.0", "1.0.0", true},
		{"up to date", "v1.0.0", "v1.0.0", false},
		{"current is newer (dev build ahead of last release)", "v1.0.0", "v2.0.0", false},
		{"dev build is not valid semver", "v1.0.0", "dev", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFakeReleaseServer(t, tt.latestTag, http.StatusOK)

			msg, err := checkLatestRelease(tt.currentVersion)
			assert.NoError(t, err)
			if tt.wantMessage {
				assert.Contains(t, msg, tt.latestTag)
				assert.Contains(t, msg, tt.currentVersion)
				assert.Contains(t, msg, releasesURL)
			} else {
				assert.Equal(t, "", msg)
			}
		})
	}

	t.Run("non-200 status returns error", func(t *testing.T) {
		withFakeReleaseServer(t, "", http.StatusInternalServerError)
		_, err := checkLatestRelease("v1.0.0")
		assert.ErrorContains(t, err, "500")
	})
}

func TestDueForCheck(t *testing.T) {
	t.Run("no cache file is due", func(t *testing.T) {
		withTempGrantedHome(t)
		assert.True(t, dueForCheck())
	})

	t.Run("recently checked is not due", func(t *testing.T) {
		withTempGrantedHome(t)
		assert.NoError(t, saveLastChecked())
		assert.False(t, dueForCheck())
	})

	t.Run("stale cache is due", func(t *testing.T) {
		withTempGrantedHome(t)
		assert.NoError(t, saveLastChecked())

		path, err := cacheFilePath()
		assert.NoError(t, err)
		b, err := json.Marshal(cacheState{LastChecked: time.Now().Add(-48 * time.Hour)})
		assert.NoError(t, err)
		assert.NoError(t, os.WriteFile(path, b, 0600))

		assert.True(t, dueForCheck())
	})

	t.Run("corrupt cache file is treated as due", func(t *testing.T) {
		withTempGrantedHome(t)
		assert.NoError(t, saveLastChecked()) // ensures the cache directory exists
		path, err := cacheFilePath()
		assert.NoError(t, err)
		assert.NoError(t, os.WriteFile(path, []byte("not json"), 0600))

		assert.True(t, dueForCheck())
	})
}

func TestCheck_SkipsWhenNotProd(t *testing.T) {
	withTempGrantedHome(t)
	withFakeReleaseServer(t, "v99.0.0", http.StatusOK)

	Check("v1.0.0", false)
	Print() // should return immediately with no message since Check no-op'd

	path, err := cacheFilePath()
	assert.NoError(t, err)
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "cache file should not have been written")
}

func TestCheck_SkipsWhenDisabledByEnv(t *testing.T) {
	withTempGrantedHome(t)
	withFakeReleaseServer(t, "v99.0.0", http.StatusOK)
	t.Setenv("GRANTED_DISABLE_UPDATE_CHECK", "true")

	Check("v1.0.0", true)
	Print()

	path, err := cacheFilePath()
	assert.NoError(t, err)
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "cache file should not have been written")
}

func TestCheck_EndToEnd_FindsNewerVersion(t *testing.T) {
	withTempGrantedHome(t)
	withFakeReleaseServer(t, "v2.0.0", http.StatusOK)

	// reset package-level message state between tests since it's a shared var
	mu.Lock()
	message = ""
	mu.Unlock()

	Check("v1.0.0", true)
	Print()

	mu.Lock()
	got := message
	mu.Unlock()
	assert.Contains(t, got, "v2.0.0")

	assert.False(t, dueForCheck(), "a successful check should update the cache")
}
