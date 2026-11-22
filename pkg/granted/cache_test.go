package granted

import (
	"testing"

	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/stretchr/testify/assert"
)

// The login session store must be listed and cleared through its own type, which
// covers both the session file and its key on Windows Credential Manager, not through
// its embedded SecureStorage.
func TestCacheStoresUseLoginSessionStorage(t *testing.T) {
	stores := cacheStores()
	assert.ElementsMatch(t, []string{"aws-iam-credentials", "sso-token", "session-credentials", "login-session"}, keysOf(stores))
	assert.IsType(t, &securestorage.LoginSessionSecureStorage{}, stores["login-session"])
}

func keysOf(m map[string]cacheStore) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
