package securestorage

import (
	"errors"
	"fmt"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// LoginSessionSecureStorage keeps `aws login` sessions in secure storage, keyed by the
// session identifier (the IAM principal ARN that `aws login` signed in as).
type LoginSessionSecureStorage struct {
	SecureStorage SecureStorage
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
func (s *LoginSessionSecureStorage) GetSession(session string) (*LoginSession, error) {
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

func (s *LoginSessionSecureStorage) StoreSession(session string, t LoginSession) error {
	if err := t.Validate(); err != nil {
		return fmt.Errorf("refusing to store incomplete login session: %w", err)
	}
	return s.SecureStorage.Store(session, &t)
}

func (s *LoginSessionSecureStorage) ClearSession(session string) error {
	err := s.SecureStorage.Clear(session)
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return nil
	}
	return err
}
