package securestorage

import (
	"time"
)

type ProviderTokenStorage struct {
	SecureStorage SecureStorage
}

type ProviderToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time `json:"expiry"`
	ProviderURL  string    `json:"provider_url"`
	TenantID     string    `json:"tenant_id,omitempty"`
}

func NewProviderTokenStorage() ProviderTokenStorage {
	return ProviderTokenStorage{
		SecureStorage: SecureStorage{StorageSuffix: "granted-provider-tokens"},
	}
}

// GetValidToken returns a stored token if it exists and is not expired.
// Returns nil if no valid token exists.
func (s *ProviderTokenStorage) GetValidToken(providerURL string) *ProviderToken {
	var token ProviderToken
	err := s.SecureStorage.Retrieve(providerURL, &token)
	if err != nil {
		return nil
	}
	if time.Now().After(token.Expiry) {
		return nil
	}
	return &token
}

func (s *ProviderTokenStorage) StoreToken(providerURL string, token ProviderToken) error {
	return s.SecureStorage.Store(providerURL, token)
}

func (s *ProviderTokenStorage) ClearToken(providerURL string) error {
	return s.SecureStorage.Clear(providerURL)
}
