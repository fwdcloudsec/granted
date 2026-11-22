package securestorage

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// fakeTokenBackend is an in-memory tokenBackend used so tests never touch
// the real OS keyring.
type fakeTokenBackend struct {
	data        map[string][]byte
	retrieveErr error
	storeErr    error
	clearErr    error
}

func (f *fakeTokenBackend) Retrieve(key string, target interface{}) error {
	if f.retrieveErr != nil {
		return f.retrieveErr
	}
	b, ok := f.data[key]
	if !ok {
		return errors.New("key not found")
	}
	return json.Unmarshal(b, target)
}

func (f *fakeTokenBackend) Store(key string, payload interface{}) error {
	if f.storeErr != nil {
		return f.storeErr
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if f.data == nil {
		f.data = map[string][]byte{}
	}
	f.data[key] = b
	return nil
}

func (f *fakeTokenBackend) Clear(key string) error {
	if f.clearErr != nil {
		return f.clearErr
	}
	delete(f.data, key)
	return nil
}

func TestProviderTokenStorage_GetValidToken(t *testing.T) {
	t.Run("no token stored", func(t *testing.T) {
		s := ProviderTokenStorage{SecureStorage: &fakeTokenBackend{}}
		assert.Nil(t, s.GetValidToken("https://provider.example.com"))
	})

	t.Run("retrieve error", func(t *testing.T) {
		s := ProviderTokenStorage{SecureStorage: &fakeTokenBackend{retrieveErr: errors.New("boom")}}
		assert.Nil(t, s.GetValidToken("https://provider.example.com"))
	})

	t.Run("expired token", func(t *testing.T) {
		backend := &fakeTokenBackend{}
		s := ProviderTokenStorage{SecureStorage: backend}
		err := s.StoreToken("https://provider.example.com", ProviderToken{
			AccessToken: "expired-token",
			Expiry:      time.Now().Add(-time.Hour),
		})
		assert.NoError(t, err)
		assert.Nil(t, s.GetValidToken("https://provider.example.com"))
	})

	t.Run("valid token", func(t *testing.T) {
		backend := &fakeTokenBackend{}
		s := ProviderTokenStorage{SecureStorage: backend}
		err := s.StoreToken("https://provider.example.com", ProviderToken{
			AccessToken: "valid-token",
			Expiry:      time.Now().Add(time.Hour),
		})
		assert.NoError(t, err)

		got := s.GetValidToken("https://provider.example.com")
		if assert.NotNil(t, got) {
			assert.Equal(t, "valid-token", got.AccessToken)
		}
	})
}

func TestProviderTokenStorage_StoreAndClearToken(t *testing.T) {
	backend := &fakeTokenBackend{}
	s := ProviderTokenStorage{SecureStorage: backend}

	err := s.StoreToken("https://provider.example.com", ProviderToken{AccessToken: "a-token", Expiry: time.Now().Add(time.Hour)})
	assert.NoError(t, err)
	assert.NotNil(t, s.GetValidToken("https://provider.example.com"))

	err = s.ClearToken("https://provider.example.com")
	assert.NoError(t, err)
	assert.Nil(t, s.GetValidToken("https://provider.example.com"))
}

func TestProviderTokenStorage_StoreToken_PropagatesBackendError(t *testing.T) {
	s := ProviderTokenStorage{SecureStorage: &fakeTokenBackend{storeErr: errors.New("keyring unavailable")}}
	err := s.StoreToken("https://provider.example.com", ProviderToken{AccessToken: "a-token"})
	assert.ErrorContains(t, err, "keyring unavailable")
}

func TestProviderTokenStorage_ClearToken_PropagatesBackendError(t *testing.T) {
	s := ProviderTokenStorage{SecureStorage: &fakeTokenBackend{clearErr: errors.New("keyring unavailable")}}
	err := s.ClearToken("https://provider.example.com")
	assert.ErrorContains(t, err, "keyring unavailable")
}
