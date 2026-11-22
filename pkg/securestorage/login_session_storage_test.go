package securestorage

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSessionARN = "arn:aws:iam::111122223333:user/file-store-test"

// newFileStoreTestStorage returns a login session store forced onto the encrypted
// file store, as on Windows Credential Manager, with an in-memory keyring standing in
// for Credential Manager and a temporary directory for the session files.
func newFileStoreTestStorage(t testing.TB) (*LoginSessionSecureStorage, *keyring.ArrayKeyring, string) {
	t.Helper()
	keys := keyring.NewArrayKeyring(nil)
	dir := t.TempDir()
	s := &LoginSessionSecureStorage{
		SecureStorage: SecureStorage{StorageSuffix: "test-login-sessions"},
		useFileStore:  func() (bool, error) { return true, nil },
		keyStore:      func() (keyring.Keyring, error) { return keys, nil },
		fileDir:       dir,
	}
	return s, keys, dir
}

// realisticSession builds a session with the field lengths measured from a real
// `aws login` session, which serializes to about 4.1 KB.
func realisticSession(accessKeyID string) LoginSession {
	return LoginSession{
		AccessToken: LoginAccessToken{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: strings.Repeat("s", 40),
			SessionToken:    strings.Repeat("t", 1408),
			AccountID:       "111122223333",
			ExpiresAt:       time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second),
		},
		TokenType:    "aws_sigv4",
		RefreshToken: strings.Repeat("r", 2111),
		ClientID:     "arn:aws:signin:::devtools/same-device",
		DPOPKey:      strings.Repeat("k", 227),
		SignInRegion: "ap-southeast-2",
	}
}

func storedKey(t *testing.T, keys keyring.Keyring, session string) string {
	t.Helper()
	item, err := keys.Get(session)
	require.NoError(t, err)
	return string(item.Data)
}

func TestLoginSessionFileStore_RoundTrip(t *testing.T) {
	s, keys, dir := newFileStoreTestStorage(t)
	tok := realisticSession("AKIDFIRST")
	data, err := json.Marshal(&tok)
	require.NoError(t, err)
	require.Greater(t, len(data), 2560, "test session must exceed the Credential Manager limit")

	require.NoError(t, s.StoreNewSession(testSessionARN, tok))

	got, err := s.GetSession(testSessionARN)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, tok, *got)

	// Only the key is in the small store, and it is far below the limit.
	key := storedKey(t, keys, testSessionARN)
	assert.Len(t, key, 44, "32 random bytes, base64 encoded")
	keyNames, err := keys.Keys()
	require.NoError(t, err)
	assert.Equal(t, []string{testSessionARN}, keyNames)

	// The session is one encrypted file whose name is safe on Windows.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.NotContains(t, entries[0].Name(), ":")
	raw, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), tok.RefreshToken[:32], "session file is encrypted")
	assert.NotContains(t, string(raw), key, "key is not in the file")
}

func TestLoginSessionFileStore_RefreshReusesKey(t *testing.T) {
	s, keys, _ := newFileStoreTestStorage(t)
	require.NoError(t, s.StoreNewSession(testSessionARN, realisticSession("AKIDFIRST")))
	key := storedKey(t, keys, testSessionARN)

	refreshed := realisticSession("AKIDREFRESHED")
	require.NoError(t, s.StoreSession(testSessionARN, refreshed))

	assert.Equal(t, key, storedKey(t, keys, testSessionARN))
	got, err := s.GetSession(testSessionARN)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "AKIDREFRESHED", got.AccessToken.AccessKeyID)
}

func TestLoginSessionFileStore_StoreWithoutKeyGeneratesOne(t *testing.T) {
	s, keys, _ := newFileStoreTestStorage(t)
	require.NoError(t, s.StoreSession(testSessionARN, realisticSession("AKIDFIRST")))
	assert.Len(t, storedKey(t, keys, testSessionARN), 44)
	got, err := s.GetSession(testSessionARN)
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestLoginSessionFileStore_NewCaptureRotatesKey(t *testing.T) {
	s, keys, dir := newFileStoreTestStorage(t)
	require.NoError(t, s.StoreNewSession(testSessionARN, realisticSession("AKIDFIRST")))
	first := storedKey(t, keys, testSessionARN)

	require.NoError(t, s.StoreNewSession(testSessionARN, realisticSession("AKIDSECOND")))
	second := storedKey(t, keys, testSessionARN)

	assert.NotEqual(t, first, second)
	got, err := s.GetSession(testSessionARN)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "AKIDSECOND", got.AccessToken.AccessKeyID)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "the new session replaces the old file")
}

func TestLoginSessionFileStore_NothingStored(t *testing.T) {
	s, _, _ := newFileStoreTestStorage(t)
	got, err := s.GetSession(testSessionARN)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestLoginSessionFileStore_MissingKeyIsNoSession(t *testing.T) {
	s, keys, _ := newFileStoreTestStorage(t)
	require.NoError(t, s.StoreNewSession(testSessionARN, realisticSession("AKIDFIRST")))
	require.NoError(t, keys.Remove(testSessionARN))

	got, err := s.GetSession(testSessionARN)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestLoginSessionFileStore_MissingFileIsNoSession(t *testing.T) {
	s, _, dir := newFileStoreTestStorage(t)
	require.NoError(t, s.StoreNewSession(testSessionARN, realisticSession("AKIDFIRST")))
	require.NoError(t, os.Remove(filepath.Join(dir, mustOnlyEntry(t, dir))))

	got, err := s.GetSession(testSessionARN)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// A crash after a new key is written but before the file is rewritten leaves a file
// encrypted under a different key.
func TestLoginSessionFileStore_WrongKeyIsNoSession(t *testing.T) {
	s, keys, _ := newFileStoreTestStorage(t)
	require.NoError(t, s.StoreNewSession(testSessionARN, realisticSession("AKIDFIRST")))
	other, err := newSessionFileKey()
	require.NoError(t, err)
	require.NoError(t, keys.Set(keyring.Item{Key: testSessionARN, Data: []byte(other)}))

	got, err := s.GetSession(testSessionARN)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestLoginSessionFileStore_CorruptFileIsNoSession(t *testing.T) {
	s, _, dir := newFileStoreTestStorage(t)
	require.NoError(t, s.StoreNewSession(testSessionARN, realisticSession("AKIDFIRST")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, mustOnlyEntry(t, dir)), []byte("not a JWE"), 0600))

	got, err := s.GetSession(testSessionARN)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestLoginSessionFileStore_ClearRemovesFileAndKey(t *testing.T) {
	s, keys, dir := newFileStoreTestStorage(t)
	require.NoError(t, s.StoreNewSession(testSessionARN, realisticSession("AKIDFIRST")))

	require.NoError(t, s.ClearSession(testSessionARN))

	keyNames, err := keys.Keys()
	require.NoError(t, err)
	assert.Empty(t, keyNames)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)

	// Clearing again, or clearing a half-written session, is not an error.
	require.NoError(t, s.ClearSession(testSessionARN))
	require.NoError(t, keys.Set(keyring.Item{Key: testSessionARN, Data: []byte("orphan")}))
	require.NoError(t, s.Clear(testSessionARN))
	keyNames, err = keys.Keys()
	require.NoError(t, err)
	assert.Empty(t, keyNames)
}

func TestLoginSessionFileStore_ListKeysOneEntryPerSession(t *testing.T) {
	s, keys, dir := newFileStoreTestStorage(t)
	other := "arn:aws:sts::444455556666:assumed-role/Admin/someone@example.com"
	require.NoError(t, s.StoreNewSession(testSessionARN, realisticSession("AKIDFIRST")))
	require.NoError(t, s.StoreNewSession(other, realisticSession("AKIDOTHER")))

	listed, err := s.ListKeys()
	require.NoError(t, err)
	assert.Equal(t, []string{testSessionARN, other}, listed)

	// A key without a file, or a file without a key, is still listed, so that
	// `granted cache clear --all` removes it.
	require.NoError(t, keys.Remove(other))
	orphanKey := "arn:aws:iam::777788889999:user/orphan-key"
	require.NoError(t, keys.Set(keyring.Item{Key: orphanKey, Data: []byte("orphan")}))
	listed, err = s.ListKeys()
	require.NoError(t, err)
	assert.Equal(t, []string{testSessionARN, orphanKey, other}, listed)

	for _, k := range listed {
		require.NoError(t, s.Clear(k))
	}
	listed, err = s.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, listed)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestSessionFileKey(t *testing.T) {
	for _, session := range []string{
		testSessionARN,
		"arn:aws:sts::444455556666:assumed-role/Admin/someone@example.com",
		"arn:aws:iam::111122223333:root",
	} {
		encoded := sessionFileKey(session)
		assert.NotContains(t, encoded, ":")
		assert.NotContains(t, encoded, "/")
		assert.NotContains(t, encoded, ".")
		decoded, err := url.PathUnescape(encoded)
		require.NoError(t, err)
		assert.Equal(t, session, decoded)
	}
}

func TestLoginSessionFileStoreEnabled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	require.NoError(t, config.SetupConfigFolder())

	setBackend := func(backend *string) {
		cfg, err := config.Load()
		require.NoError(t, err)
		if backend == nil {
			cfg.Keyring = nil
		} else {
			cfg.Keyring = &config.KeyringConfig{Backend: backend}
		}
		require.NoError(t, cfg.Save())
	}
	s := NewSecureLoginSessionStorage()
	enabled := func() bool {
		got, err := s.fileStoreEnabled()
		require.NoError(t, err)
		return got
	}

	wincred, file, keychain := "wincred", "file", "keychain"
	setBackend(&wincred)
	assert.True(t, enabled(), "explicit wincred")
	setBackend(&file)
	assert.False(t, enabled(), "explicit file")
	setBackend(&keychain)
	assert.False(t, enabled(), "explicit keychain")
	setBackend(nil)
	assert.Equal(t, runtime.GOOS == "windows", enabled(), "default backend is wincred only on Windows")
}

func mustOnlyEntry(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	return entries[0].Name()
}

// BenchmarkLoginSessionFileStoreGet measures reading a session from the file store,
// which `granted credential-process` does on every call on Windows Credential Manager.
// Almost all of it is the PBES2 key derivation of the file backend.
func BenchmarkLoginSessionFileStoreGet(b *testing.B) {
	s, _, _ := newFileStoreTestStorage(b)
	require.NoError(b, s.StoreNewSession(testSessionARN, realisticSession("AKIDBENCH")))
	for b.Loop() {
		got, err := s.GetSession(testSessionARN)
		if err != nil || got == nil {
			b.Fatalf("GetSession: %v, %v", got, err)
		}
	}
}

// BenchmarkLoginSessionFileStoreRefresh measures writing a refreshed session.
func BenchmarkLoginSessionFileStoreRefresh(b *testing.B) {
	s, _, _ := newFileStoreTestStorage(b)
	tok := realisticSession("AKIDBENCH")
	require.NoError(b, s.StoreNewSession(testSessionARN, tok))
	for b.Loop() {
		if err := s.StoreSession(testSessionARN, tok); err != nil {
			b.Fatal(err)
		}
	}
}
