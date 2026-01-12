package securestorage

import (
	"encoding/json"
	"os"
	"path"

	"github.com/99designs/keyring"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/pkg/errors"
)

type SecureStorage struct {
	StorageSuffix string
}

// returns false if the key is not found, true if it is found, or false and an error if there was a keyring related error
func (s *SecureStorage) HasKey(key string) (bool, error) {
	ring, err := s.openKeyring()
	if err != nil {
		return false, err
	}
	_, err = ring.Get(key)
	if err == keyring.ErrKeyNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// returns keyring.ErrKeyNotFound if not found
func (s *SecureStorage) Retrieve(key string, target interface{}) error {
	ring, err := s.openKeyring()
	if err != nil {
		return err
	}
	keyringItem, err := ring.Get(key)
	if err != nil {
		return err
	}
	return json.Unmarshal(keyringItem.Data, &target)
}

func (s *SecureStorage) Store(key string, payload interface{}) error {
	ring, err := s.openKeyring()
	if err != nil {
		return err
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return ring.Set(keyring.Item{
		Key:  key, // store with the corresponding key
		Data: b,   // store the bytes
	})
}

func (s *SecureStorage) Clear(key string) error {
	ring, err := s.openKeyring()
	if err != nil {
		return err
	}
	return ring.Remove(key)
}

func (s *SecureStorage) List() ([]keyring.Item, error) {
	tokenList := []keyring.Item{}
	ring, err := s.openKeyring()
	if err != nil {
		return nil, err
	}
	keys, err := ring.Keys()
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		item, err := ring.Get(k)
		if err != nil {
			return nil, err
		}
		tokenList = append(tokenList, item)

	}
	return tokenList, nil
}

func (s *SecureStorage) ListKeys() ([]string, error) {
	ring, err := s.openKeyring()
	if err != nil {
		return nil, err
	}
	return ring.Keys()
}

func (s *SecureStorage) openKeyring() (keyring.Keyring, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	grantedFolder, err := config.GrantedConfigFolder()
	if err != nil {
		return nil, err
	}

	secureStoragePath := path.Join(grantedFolder, "secure-storage-"+s.StorageSuffix)
	name := "granted-" + s.StorageSuffix
	c := keyring.Config{
		ServiceName: name,

		// MacOS keychain
		KeychainName:             "login",
		KeychainTrustApplication: true,

		// KDE Wallet
		KWalletAppID:  name,
		KWalletFolder: name,

		// Windows
		WinCredPrefix: name,

		// freedesktop.org's Secret Service
		LibSecretCollectionName: name,

		// Pass (https://www.passwordstore.org/)
		PassPrefix: name,

		// Fallback encrypted file
		FileDir: secureStoragePath,

		FilePasswordFunc: keyring.FixedStringPrompt(os.Getenv("CF_KEYRING_FILE_PASSWORD")),
	}

	// enable debug logging if the verbose flag is set in the CLI
	keyring.Debug = clio.IsDebug()

	if cfg.Keyring != nil {
		if cfg.Keyring.Backend != nil {
			c.AllowedBackends = []keyring.BackendType{keyring.BackendType(*cfg.Keyring.Backend)}
		}
		if cfg.Keyring.KeychainName != nil {
			c.KeychainName = *cfg.Keyring.KeychainName
		}
		if cfg.Keyring.FileDir != nil {
			c.FileDir = *cfg.Keyring.FileDir
		}
		if cfg.Keyring.LibSecretCollectionName != nil {
			c.LibSecretCollectionName = *cfg.Keyring.LibSecretCollectionName
		}
		if cfg.Keyring.PassDir != nil {
			c.PassDir = *cfg.Keyring.PassDir
		}
	}

	k, err := keyring.Open(c)
	if err != nil {
		return nil, errors.Wrap(err, "opening keyring")
	}

	return k, nil
}

// Keyring returns the underlying keyring associated with the storage.
func (s *SecureStorage) Keyring() (keyring.Keyring, error) {
	return s.openKeyring()
}
