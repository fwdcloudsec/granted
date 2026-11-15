package securestorage

import (
	"fmt"
	"sync"
	"testing"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureWarnings replaces warnf for the duration of the test, resets the
// one-time warning guard, and returns a pointer to the captured messages.
func captureWarnings(t *testing.T) *[]string {
	t.Helper()
	var warnings []string
	oldWarnf := warnf
	warnf = func(template string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(template, args...))
	}
	fileKeyringPasswordWarning = sync.Once{}
	t.Cleanup(func() {
		warnf = oldWarnf
		fileKeyringPasswordWarning = sync.Once{}
	})
	return &warnings
}

func TestFileKeyringPassword(t *testing.T) {
	tests := []struct {
		name         string
		password     string
		wantWarnings int
	}{
		{name: "empty password warns once", password: "", wantWarnings: 1},
		{name: "password set does not warn", password: "s3cret", wantWarnings: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := captureWarnings(t)
			t.Setenv(fileKeyringPasswordEnvVar, tt.password)

			for i := 0; i < 3; i++ {
				got, err := fileKeyringPassword("Enter passphrase")
				require.NoError(t, err)
				assert.Equal(t, tt.password, got)
			}

			assert.Len(t, *warnings, tt.wantWarnings)
			for _, w := range *warnings {
				assert.Contains(t, w, fileKeyringPasswordEnvVar)
			}
		})
	}
}

// TestFileKeyringPasswordWithFileBackend checks the warning is emitted when
// the keyring library actually uses the file backend.
func TestFileKeyringPasswordWithFileBackend(t *testing.T) {
	warnings := captureWarnings(t)
	t.Setenv(fileKeyringPasswordEnvVar, "")

	ring, err := keyring.Open(keyring.Config{
		AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
		FileDir:          t.TempDir(),
		FilePasswordFunc: fileKeyringPassword,
	})
	require.NoError(t, err)
	assert.Empty(t, *warnings, "opening the keyring should not warn")

	require.NoError(t, ring.Set(keyring.Item{Key: "key", Data: []byte("value")}))
	item, err := ring.Get("key")
	require.NoError(t, err)
	assert.Equal(t, []byte("value"), item.Data)

	assert.Len(t, *warnings, 1)
}
