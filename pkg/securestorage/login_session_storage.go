package securestorage

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/config"
)

// LoginSessionSecureStorage keeps `aws login` sessions in secure storage, keyed by the
// session identifier (the IAM principal ARN that `aws login` signed in as).
//
// When Granted's keyring is Windows Credential Manager (wincred), a session does not
// fit: Credential Manager caps one credential at 2560 bytes and a real session is
// about 4 KB. In that case the session is written with the keyring library's
// encrypted file backend instead, under a random key generated for that session, and
// only the key is kept in Credential Manager. See fileStoreEnabled.
type LoginSessionSecureStorage struct {
	SecureStorage SecureStorage

	// Seams for tests. Zero values select the production behaviour.

	// useFileStore reports whether sessions go to the encrypted file store.
	useFileStore func() (bool, error)
	// keyStore opens the keyring that holds the per-session file keys.
	keyStore func() (keyring.Keyring, error)
	// fileDir is the directory of the encrypted session files.
	fileDir string
}

func NewSecureLoginSessionStorage() LoginSessionSecureStorage {
	return LoginSessionSecureStorage{
		SecureStorage: SecureStorage{
			StorageSuffix: "aws-login-sessions",
		},
	}
}

// LoginSession mirrors the JSON the AWS CLI writes to its login cache, so a file
// captured from `aws login` unmarshals into it directly.
type LoginSession struct {
	AccessToken   LoginAccessToken `json:"accessToken"`
	TokenType     string           `json:"tokenType,omitempty"`
	RefreshToken  string           `json:"refreshToken"`
	IdentityToken string           `json:"identityToken,omitempty"`
	ClientID      string           `json:"clientId"`
	// DPOPKey is the PEM encoded EC private key that proves possession of the refresh token.
	DPOPKey string `json:"dpopKey"`
	// SignInRegion is the region the session was created in. Refresh tokens are
	// regional, so refreshes must go back to the same region.
	SignInRegion string `json:"signInRegion,omitempty"`
}

// LoginAccessToken is the AWS credential part of a login session.
type LoginAccessToken struct {
	AccessKeyID     string    `json:"accessKeyId"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
	AccountID       string    `json:"accountId"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

// Validate checks that every field needed to use and refresh the session is present.
func (t *LoginSession) Validate() error {
	switch {
	case t.AccessToken.AccessKeyID == "":
		return fmt.Errorf("missing accessToken.accessKeyId")
	case t.AccessToken.SecretAccessKey == "":
		return fmt.Errorf("missing accessToken.secretAccessKey")
	case t.AccessToken.SessionToken == "":
		return fmt.Errorf("missing accessToken.sessionToken")
	case t.AccessToken.ExpiresAt.IsZero():
		return fmt.Errorf("missing accessToken.expiresAt")
	case t.ClientID == "":
		return fmt.Errorf("missing clientId")
	case t.RefreshToken == "":
		return fmt.Errorf("missing refreshToken")
	case t.DPOPKey == "":
		return fmt.Errorf("missing dpopKey")
	}
	return nil
}

// Credentials returns the session's access token as AWS credentials.
func (t *LoginSession) Credentials() aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     t.AccessToken.AccessKeyID,
		SecretAccessKey: t.AccessToken.SecretAccessKey,
		SessionToken:    t.AccessToken.SessionToken,
		Source:          "GrantedLoginSession",
		CanExpire:       true,
		Expires:         t.AccessToken.ExpiresAt,
		AccountID:       t.AccessToken.AccountID,
	}
}

// GetSession returns the stored session, or nil when none is stored.
//
// With the file store, a session whose key or file is missing, or whose file cannot
// be decrypted (for example after a crash between writing the key and the file), is
// reported as nil so that Granted runs `aws login` again and overwrites it.
func (s *LoginSessionSecureStorage) GetSession(session string) (*LoginSession, error) {
	useFile, err := s.fileStoreEnabled()
	if err != nil {
		return nil, err
	}
	if !useFile {
		var t LoginSession
		err := s.SecureStorage.Retrieve(session, &t)
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &t, nil
	}

	keys, err := s.openKeyStore()
	if err != nil {
		return nil, err
	}
	key, err := keys.Get(session)
	if errors.Is(err, keyring.ErrKeyNotFound) {
		clio.Debugw("no key for login session file in secure storage, treating as no session", "session", session)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	files, err := s.openFileStore(string(key.Data))
	if err != nil {
		return nil, err
	}
	item, err := files.Get(sessionFileKey(session))
	if errors.Is(err, keyring.ErrKeyNotFound) {
		clio.Debugw("no login session file, treating as no session", "session", session)
		return nil, nil
	}
	if err != nil {
		clio.Debugw("could not read login session file, treating as no session", "session", session, "error", err)
		return nil, nil
	}
	var t LoginSession
	if err := json.Unmarshal(item.Data, &t); err != nil {
		clio.Debugw("could not parse login session file, treating as no session", "session", session, "error", err)
		return nil, nil
	}
	return &t, nil
}

// StoreSession stores an updated version of a session, such as a refreshed one. With
// the file store it keeps the session's existing key, and generates one only if the
// session has none.
func (s *LoginSessionSecureStorage) StoreSession(session string, t LoginSession) error {
	return s.store(session, t, false)
}

// StoreNewSession stores a session captured from a fresh `aws login`, replacing any
// session stored under the same identifier. With the file store it always generates
// a new key, so each login session is encrypted under its own key.
func (s *LoginSessionSecureStorage) StoreNewSession(session string, t LoginSession) error {
	return s.store(session, t, true)
}

func (s *LoginSessionSecureStorage) store(session string, t LoginSession, newKey bool) error {
	if err := t.Validate(); err != nil {
		return fmt.Errorf("refusing to store incomplete login session: %w", err)
	}
	useFile, err := s.fileStoreEnabled()
	if err != nil {
		return err
	}
	if !useFile {
		return s.SecureStorage.Store(session, &t)
	}

	keys, err := s.openKeyStore()
	if err != nil {
		return err
	}
	var key string
	if !newKey {
		item, err := keys.Get(session)
		switch {
		case err == nil:
			key = string(item.Data)
		case errors.Is(err, keyring.ErrKeyNotFound):
		default:
			return err
		}
	}
	if key == "" {
		key, err = newSessionFileKey()
		if err != nil {
			return err
		}
		if err := keys.Set(keyring.Item{Key: session, Data: []byte(key)}); err != nil {
			return fmt.Errorf("storing login session key: %w", err)
		}
	}

	files, err := s.openFileStore(key)
	if err != nil {
		return err
	}
	data, err := json.Marshal(&t)
	if err != nil {
		return err
	}
	if err := files.Set(keyring.Item{Key: sessionFileKey(session), Data: data}); err != nil {
		return fmt.Errorf("storing login session file: %w", err)
	}
	return nil
}

// ClearSession removes a session. It is not an error if there is nothing to remove.
// With the file store it removes both the file and its key.
func (s *LoginSessionSecureStorage) ClearSession(session string) error {
	useFile, err := s.fileStoreEnabled()
	if err != nil {
		return err
	}
	if !useFile {
		err := s.SecureStorage.Clear(session)
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return nil
		}
		return err
	}

	var errs []error
	files, err := s.openFileStore("")
	if err == nil {
		err = files.Remove(sessionFileKey(session))
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, keyring.ErrKeyNotFound) {
		errs = append(errs, fmt.Errorf("removing login session file: %w", err))
	}
	keys, err := s.openKeyStore()
	if err == nil {
		err = keys.Remove(session)
	}
	if err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
		errs = append(errs, fmt.Errorf("removing login session key: %w", err))
	}
	return errors.Join(errs...)
}

// ListKeys returns the identifiers of the stored sessions. With the file store, a
// session counts if either its key or its file exists, so that a half-written session
// is still listed and `granted cache clear` removes it.
func (s *LoginSessionSecureStorage) ListKeys() ([]string, error) {
	useFile, err := s.fileStoreEnabled()
	if err != nil {
		return nil, err
	}
	if !useFile {
		return s.SecureStorage.ListKeys()
	}

	seen := map[string]bool{}
	keys, err := s.openKeyStore()
	if err != nil {
		return nil, err
	}
	keyNames, err := keys.Keys()
	if err != nil {
		return nil, err
	}
	for _, k := range keyNames {
		seen[k] = true
	}
	files, err := s.openFileStore("")
	if err != nil {
		return nil, err
	}
	fileNames, err := files.Keys()
	if err != nil {
		return nil, err
	}
	for _, f := range fileNames {
		session, err := url.PathUnescape(f)
		if err != nil {
			clio.Debugw("ignoring unrecognised file in login session file store", "name", f, "error", err)
			continue
		}
		seen[session] = true
	}

	sessions := make([]string, 0, len(seen))
	for k := range seen {
		sessions = append(sessions, k)
	}
	sort.Strings(sessions)
	return sessions, nil
}

// Clear removes a session; it lets `granted cache clear` treat this store like the
// others.
func (s *LoginSessionSecureStorage) Clear(session string) error {
	return s.ClearSession(session)
}

// fileStoreEnabled reports whether sessions go to the encrypted file store, which is
// the case when Granted's keyring resolves to Windows Credential Manager: either it is
// configured explicitly, or no backend is configured on Windows, where the keyring
// library tries wincred first.
func (s *LoginSessionSecureStorage) fileStoreEnabled() (bool, error) {
	if s.useFileStore != nil {
		return s.useFileStore()
	}
	cfg, err := config.Load()
	if err != nil {
		return false, err
	}
	if cfg.Keyring != nil && cfg.Keyring.Backend != nil {
		return *cfg.Keyring.Backend == string(keyring.WinCredBackend), nil
	}
	return runtime.GOOS == "windows", nil
}

// openKeyStore opens the keyring holding the per-session file keys: Granted's normal
// keyring (Credential Manager) under its own service name, so the keys can never be
// mistaken for sessions.
func (s *LoginSessionSecureStorage) openKeyStore() (keyring.Keyring, error) {
	if s.keyStore != nil {
		return s.keyStore()
	}
	keys := SecureStorage{StorageSuffix: s.SecureStorage.StorageSuffix + "-keys"}
	return keys.openKeyring()
}

func (s *LoginSessionSecureStorage) sessionFileDir() (string, error) {
	if s.fileDir != "" {
		return s.fileDir, nil
	}
	folder, err := config.GrantedConfigFolder()
	if err != nil {
		return "", err
	}
	// Distinct from the directory of the normal file backend, which uses a single
	// user-supplied password for every item.
	return filepath.Join(folder, "secure-storage-"+s.SecureStorage.StorageSuffix+"-file"), nil
}

// openFileStore opens the encrypted file store with the given session key. Each
// session file is encrypted separately, so the store is opened per session. Removing
// and listing files need no key; pass "" for those.
func (s *LoginSessionSecureStorage) openFileStore(key string) (keyring.Keyring, error) {
	dir, err := s.sessionFileDir()
	if err != nil {
		return nil, err
	}
	return keyring.Open(keyring.Config{
		ServiceName:     "granted-" + s.SecureStorage.StorageSuffix,
		AllowedBackends: []keyring.BackendType{keyring.FileBackend},
		FileDir:         dir,
		FilePasswordFunc: func(string) (string, error) {
			if key == "" {
				return "", errors.New("login session file store opened without a session key")
			}
			return key, nil
		},
	})
}

// newSessionFileKey returns a random 256-bit key, base64 encoded, used as the
// password of one session's file.
func newSessionFileKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating login session key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// sessionFileKey returns the file store item name for a session. Session identifiers
// are ARNs, whose ':' and '/' are not allowed in Windows file names, so everything
// except ASCII letters, digits, '-' and '_' is percent-encoded. url.PathUnescape
// reverses it.
func sessionFileKey(session string) string {
	var b strings.Builder
	for i := 0; i < len(session); i++ {
		c := session[i]
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '-' || c == '_' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
