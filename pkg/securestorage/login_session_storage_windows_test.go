//go:build windows

package securestorage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/stretchr/testify/require"
)

// These tests write to the real Windows Credential Manager, which limits a single
// credential blob to 2560 bytes. They only run when GRANTED_WINCRED_TEST=1 so that
// they never touch a developer's own credential store by accident; CI sets it on a
// throwaway runner.

func requireWinCredTest(t *testing.T) {
	t.Helper()
	if os.Getenv("GRANTED_WINCRED_TEST") != "1" {
		t.Skip("set GRANTED_WINCRED_TEST=1 to run tests against the real Windows Credential Manager")
	}
	// Point Granted's config folder at a temp dir. Credential Manager is tied to the
	// logged-on user, not to these variables, so this only isolates the config file.
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	require.NoError(t, config.SetupConfigFolder())
}

// newWinCredTestStorage returns a login session store under a unique name, and
// clears the given key from it when the test ends.
func newWinCredTestStorage(t *testing.T, key string) LoginSessionSecureStorage {
	t.Helper()
	s := LoginSessionSecureStorage{
		SecureStorage: SecureStorage{
			StorageSuffix: fmt.Sprintf("test-login-sessions-%d", time.Now().UnixNano()),
		},
	}
	t.Cleanup(func() { _ = s.ClearSession(key) })
	return s
}

func testDPOPKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// testLoginSession builds a session whose token fields have the given lengths.
func testLoginSession(t *testing.T, sessionTokenLen, refreshTokenLen int) LoginSession {
	t.Helper()
	return LoginSession{
		AccessToken: LoginAccessToken{
			AccessKeyID:     "ASIAEXAMPLEEXAMPLE00",
			SecretAccessKey: strings.Repeat("s", 40),
			SessionToken:    strings.Repeat("t", sessionTokenLen),
			AccountID:       "111122223333",
			ExpiresAt:       time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second),
		},
		TokenType:    "aws_sigv4",
		RefreshToken: strings.Repeat("r", refreshTokenLen),
		ClientID:     "arn:aws:signin:::devtools/same-device",
		DPOPKey:      testDPOPKeyPEM(t),
		SignInRegion: "ap-southeast-2",
	}
}

func storeAndReadBack(t *testing.T, tok LoginSession) {
	t.Helper()
	data, err := json.Marshal(&tok)
	require.NoError(t, err)
	t.Logf("serialized session is %d bytes (Credential Manager limit: 2560)", len(data))

	key := "arn:aws:iam::111122223333:user/wincred-test"
	s := newWinCredTestStorage(t, key)

	require.NoError(t, s.StoreSession(key, tok))

	got, err := s.GetSession(key)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, tok, *got)

	require.NoError(t, s.ClearSession(key))
	got, err = s.GetSession(key)
	require.NoError(t, err)
	require.Nil(t, got)
}

// TestWinCredLoginSession_Small is the control: a session well under the limit
// proves that Credential Manager works on this machine, so a failure in the
// realistic test is down to size and nothing else.
func TestWinCredLoginSession_Small(t *testing.T) {
	requireWinCredTest(t)
	storeAndReadBack(t, testLoginSession(t, 200, 200))
}

// TestWinCredLoginSession_RealisticSize uses the field lengths measured from a real
// `aws login` session (session token 1408, refresh token 2111; about 4.1 KB in all).
func TestWinCredLoginSession_RealisticSize(t *testing.T) {
	requireWinCredTest(t)
	storeAndReadBack(t, testLoginSession(t, 1408, 2111))
}
