package cfaws

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials/logincreds"
	signintypes "github.com/aws/aws-sdk-go-v2/service/signin/types"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLoginStore is an in-memory stand-in for the secure storage of login sessions.
type fakeLoginStore struct {
	sessions map[string]securestorage.LoginSession
	getErr   error
	stores   int
}

func (f *fakeLoginStore) GetSession(session string) (*securestorage.LoginSession, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	t, ok := f.sessions[session]
	if !ok {
		return nil, nil
	}
	return &t, nil
}

func (f *fakeLoginStore) StoreSession(session string, t securestorage.LoginSession) error {
	if err := t.Validate(); err != nil {
		return err
	}
	f.stores++
	f.sessions[session] = t
	return nil
}

func (f *fakeLoginStore) ClearSession(session string) error {
	delete(f.sessions, session)
	return nil
}

func stubLoginStore(t *testing.T) *fakeLoginStore {
	t.Helper()
	f := &fakeLoginStore{sessions: map[string]securestorage.LoginSession{}}
	orig := newLoginSessionStore
	newLoginSessionStore = func() loginSessionStore { return f }
	t.Cleanup(func() { newLoginSessionStore = orig })
	return f
}

// stubLoginTempRoot points capture directories at a temporary folder and returns it.
func stubLoginTempRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "login-tmp")
	orig := loginTempRoot
	loginTempRoot = func() (string, error) { return root, nil }
	t.Cleanup(func() { loginTempRoot = orig })
	return root
}

// managedSession builds a complete stored login session.
func managedSession(t *testing.T, expiresAt time.Time, accessKeyID string) securestorage.LoginSession {
	t.Helper()
	return securestorage.LoginSession{
		AccessToken: securestorage.LoginAccessToken{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: "SECRET",
			SessionToken:    "SESSION",
			AccountID:       "123456789012",
			ExpiresAt:       expiresAt.UTC(),
		},
		TokenType:    "aws_sigv4",
		RefreshToken: "REFRESH",
		ClientID:     "arn:aws:signin:::devtools/same-device",
		DPOPKey:      testDPOPKeyPEM(t),
		SignInRegion: "ap-southeast-2",
	}
}

// stubRegionRecorder records the region each refresh client was built for.
func stubRegionRecorder(t *testing.T, client logincreds.TokenAPIClient) *[]string {
	t.Helper()
	regions := &[]string{}
	orig := newSigninTokenClient
	newSigninTokenClient = func(region string) logincreds.TokenAPIClient {
		*regions = append(*regions, region)
		return client
	}
	t.Cleanup(func() { newSigninTokenClient = orig })
	return regions
}

func TestIsLoginRootProfile(t *testing.T) {
	assert.True(t, IsLoginRootProfile(loadTestProfile(t, "managed-login")))
	assert.True(t, IsLoginRootProfile(loadTestProfile(t, "login-prof")))
	assert.False(t, IsLoginRootProfile(loadTestProfile(t, "managed-role")), "chained roles are cached by credential-process")
	assert.False(t, IsLoginRootProfile(loadTestProfile(t, "plain-iam")))
	assert.False(t, IsLoginRootProfile(nil))
}

func TestLoadProfiles_ManagedLoginProfileTypes(t *testing.T) {
	ctx := context.Background()
	profiles := writeLoginFixtures(t)

	root, err := profiles.LoadInitialisedProfile(ctx, "managed-login")
	require.NoError(t, err)
	assert.Equal(t, ProfileTypeAWSLogin, root.ProfileType)
	assert.False(t, root.HasSecureStorageIAMCredentials, "a managed login profile is not an imported IAM user")
	assert.True(t, IsManagedLoginProfile(root))
	assert.Equal(t, testLoginSession, loginSessionARN(root))
	assert.Empty(t, root.Parents)

	// The source has credential_process, so the SDK accepts it as a source_profile
	// without Granted's login_session fallback.
	child, err := profiles.LoadInitialisedProfile(ctx, "managed-role")
	require.NoError(t, err)
	assert.Equal(t, ProfileTypeAWSLogin, child.ProfileType)
	require.Len(t, child.Parents, 1)
	assert.Equal(t, "managed-login", child.Parents[0].Name)
	assert.Equal(t, testLoginRoleARN, child.AWSConfig.RoleARN)
	assert.False(t, IsManagedLoginProfile(child))

	native := loadTestProfile(t, "login-prof")
	assert.False(t, IsManagedLoginProfile(native))
	assert.Equal(t, testLoginSession, loginSessionARN(native))
}

func TestManagedLogin_UsesStoredSession(t *testing.T) {
	p := loadTestProfile(t, "managed-login")
	store := stubLoginStore(t)
	store.sessions[testLoginSession] = managedSession(t, time.Now().Add(10*time.Minute), "AKID")
	stubSigninClient(t, &fakeTokenClient{t: t})
	failIfLoginRuns(t)

	creds, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.NoError(t, err)
	assert.Equal(t, "AKID", creds.AccessKeyID)
	assert.Equal(t, "123456789012", creds.AccountID)
	assert.True(t, creds.CanExpire)
	assert.Equal(t, 0, store.stores, "a fresh session is not rewritten")
}

func TestManagedLogin_NoSession_NonInteractive(t *testing.T) {
	p := loadTestProfile(t, "managed-login")
	stubLoginStore(t)
	stubSigninClient(t, &fakeTokenClient{t: t})
	calls := stubLogin(t, nil)

	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{UsingCredentialProcess: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assume managed-login")
	assert.Empty(t, *calls)
}

func TestManagedLogin_NoSession_CapturesLogin(t *testing.T) {
	p := loadTestProfile(t, "managed-login")
	store := stubLoginStore(t)
	tmpRoot := stubLoginTempRoot(t)
	stubSigninClient(t, &fakeTokenClient{t: t})

	var scratchConfig string
	var tmpDir string
	calls := stubLogin(t, func(call loginCall) error {
		cacheDir := envValue(call.env, "AWS_LOGIN_CACHE_DIRECTORY")
		require.NotEmpty(t, cacheDir)
		tmpDir = filepath.Dir(cacheDir)
		assert.Equal(t, tmpRoot, filepath.Dir(tmpDir), "capture dir lives under the login temp root")

		data, err := os.ReadFile(envValue(call.env, "AWS_CONFIG_FILE"))
		require.NoError(t, err)
		scratchConfig = string(data)
		assert.Equal(t, filepath.Join(tmpDir, "credentials"), envValue(call.env, "AWS_SHARED_CREDENTIALS_FILE"))

		writeLoginTokenAt(t, cacheDir, testLoginSession, time.Now().Add(15*time.Minute), "CAPTURED")
		return nil
	})

	creds, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.NoError(t, err)
	require.Len(t, *calls, 1)
	assert.Equal(t, "managed-login", (*calls)[0].profile)
	assert.False(t, (*calls)[0].remote)

	assert.Contains(t, scratchConfig, "[profile managed-login]")
	assert.Contains(t, scratchConfig, "login_session = "+testLoginSession)
	assert.Contains(t, scratchConfig, "region = us-east-1")

	assert.Equal(t, "CAPTURED", creds.AccessKeyID)
	stored, ok := store.sessions[testLoginSession]
	require.True(t, ok, "session stored in secure storage")
	assert.Equal(t, "CAPTURED", stored.AccessToken.AccessKeyID)
	assert.Equal(t, "us-east-1", stored.SignInRegion, "region recorded for later refreshes")

	_, statErr := os.Stat(tmpDir)
	assert.True(t, os.IsNotExist(statErr), "capture dir removed after login")
}

func TestManagedLogin_DefaultProfileScratchSection(t *testing.T) {
	writeSharedConfig(t, "[default]\n"+GrantedLoginSessionKey+" = "+testLoginSession+"\nregion = us-east-1\n")
	t.Setenv("OKTA_CONFIG", filepath.Join(t.TempDir(), "missing-okta-config"))
	profiles, err := LoadProfiles()
	require.NoError(t, err)
	p, err := profiles.LoadInitialisedProfile(context.Background(), "default")
	require.NoError(t, err)

	stubLoginStore(t)
	stubLoginTempRoot(t)
	stubSigninClient(t, &fakeTokenClient{t: t})
	var scratchConfig string
	stubLogin(t, func(call loginCall) error {
		data, err := os.ReadFile(envValue(call.env, "AWS_CONFIG_FILE"))
		require.NoError(t, err)
		scratchConfig = string(data)
		writeLoginTokenAt(t, envValue(call.env, "AWS_LOGIN_CACHE_DIRECTORY"), testLoginSession, time.Now().Add(15*time.Minute), "AKID")
		return nil
	})

	_, err = (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(scratchConfig, "[default]\n"), scratchConfig)
}

func TestManagedLogin_IdentityMismatchRejected(t *testing.T) {
	p := loadTestProfile(t, "managed-login")
	store := stubLoginStore(t)
	stubLoginTempRoot(t)
	stubSigninClient(t, &fakeTokenClient{t: t})
	var tmpDir string
	stubLogin(t, func(call loginCall) error {
		cacheDir := envValue(call.env, "AWS_LOGIN_CACHE_DIRECTORY")
		tmpDir = filepath.Dir(cacheDir)
		// The browser signed in as somebody else and the user accepted the CLI's
		// overwrite prompt, so the token landed under a different session hash.
		writeLoginTokenAt(t, cacheDir, "arn:aws:iam::999999999999:user/mallory", time.Now().Add(15*time.Minute), "WRONG")
		return nil
	})

	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "different identity")
	assert.Contains(t, err.Error(), testLoginSession)
	assert.Empty(t, store.sessions, "nothing stored for a mismatched identity")
	_, statErr := os.Stat(tmpDir)
	assert.True(t, os.IsNotExist(statErr), "capture dir removed on failure too")
}

func TestManagedLogin_LoginDeclinedOrFailed(t *testing.T) {
	p := loadTestProfile(t, "managed-login")
	store := stubLoginStore(t)
	stubLoginTempRoot(t)
	stubSigninClient(t, &fakeTokenClient{t: t})

	// The user answered "n" to the CLI's prompt: it exits 0 without writing a token.
	stubLogin(t, nil)
	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not create a session")
	assert.Empty(t, store.sessions)

	// The CLI itself failed.
	stubLogin(t, func(loginCall) error { return errors.New("aws login exploded") })
	_, err = (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.EqualError(t, err, "aws login exploded")
}

func TestManagedLogin_RemoteAndPassthrough(t *testing.T) {
	p := loadTestProfile(t, "managed-login")
	stubLoginStore(t)
	stubLoginTempRoot(t)
	stubSigninClient(t, &fakeTokenClient{t: t})
	calls := stubLogin(t, func(call loginCall) error {
		writeLoginTokenAt(t, envValue(call.env, "AWS_LOGIN_CACHE_DIRECTORY"), testLoginSession, time.Now().Add(15*time.Minute), "AKID")
		return nil
	})

	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{UseDeviceCode: true, Args: []string{"--redirect-port", "5555"}})
	require.NoError(t, err)
	require.Len(t, *calls, 1)
	assert.True(t, (*calls)[0].remote)
	assert.Equal(t, []string{"--redirect-port", "5555"}, (*calls)[0].passthrough)
}

func TestManagedLogin_RefreshesNearExpiry(t *testing.T) {
	p := loadTestProfile(t, "managed-login")
	store := stubLoginStore(t)
	store.sessions[testLoginSession] = managedSession(t, time.Now().Add(2*time.Minute), "OLD")
	client := &fakeTokenClient{t: t, out: refreshedTokenOutput("NEW")}
	regions := stubRegionRecorder(t, client)
	failIfLoginRuns(t)

	creds, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.NoError(t, err)
	assert.Equal(t, "NEW", creds.AccessKeyID)
	assert.Equal(t, "NEWSECRET", creds.SecretAccessKey)
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), creds.Expires, time.Minute)

	require.Equal(t, 1, client.calls)
	assert.Equal(t, "refresh_token", *client.in.TokenInput.GrantType)
	assert.Equal(t, "REFRESH", *client.in.TokenInput.RefreshToken)
	assert.Equal(t, "arn:aws:signin:::devtools/same-device", *client.in.TokenInput.ClientId)
	assert.Equal(t, 1, client.optCount, "DPoP client option passed on the refresh call")
	assert.Equal(t, []string{"ap-southeast-2"}, *regions, "refresh goes to the region the session was created in")

	stored := store.sessions[testLoginSession]
	assert.Equal(t, "NEW", stored.AccessToken.AccessKeyID)
	assert.Equal(t, "NEWREFRESH", stored.RefreshToken)
	assert.Equal(t, "ap-southeast-2", stored.SignInRegion)
	assert.Equal(t, 1, store.stores)
}

func TestManagedLogin_RefreshKeepsRefreshTokenWhenNotRotated(t *testing.T) {
	tok := managedSession(t, time.Now().Add(-time.Minute), "OLD")
	out := refreshedTokenOutput("NEW")
	out.TokenOutput.RefreshToken = nil
	client := &fakeTokenClient{t: t, out: out}

	updated, err := refreshLoginSession(context.Background(), client, &tok)
	require.NoError(t, err)
	assert.Equal(t, "REFRESH", updated.RefreshToken)
	assert.Equal(t, "NEW", updated.AccessToken.AccessKeyID)
	assert.Equal(t, "OLD", tok.AccessToken.AccessKeyID, "input is not mutated")
}

func TestManagedLogin_SessionExpired_TriggersLogin(t *testing.T) {
	p := loadTestProfile(t, "managed-login")
	store := stubLoginStore(t)
	store.sessions[testLoginSession] = managedSession(t, time.Now().Add(-time.Minute), "OLD")
	stubLoginTempRoot(t)
	stubSigninClient(t, &fakeTokenClient{t: t, err: &signintypes.AccessDeniedException{Error_: signintypes.OAuth2ErrorCodeTokenExpired}})
	calls := stubLogin(t, func(call loginCall) error {
		writeLoginTokenAt(t, envValue(call.env, "AWS_LOGIN_CACHE_DIRECTORY"), testLoginSession, time.Now().Add(15*time.Minute), "FRESH")
		return nil
	})

	creds, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.NoError(t, err)
	assert.Len(t, *calls, 1)
	assert.Equal(t, "FRESH", creds.AccessKeyID)
	assert.Equal(t, "FRESH", store.sessions[testLoginSession].AccessToken.AccessKeyID)
}

func TestManagedLogin_OtherRefreshError_NoLogin(t *testing.T) {
	p := loadTestProfile(t, "managed-login")
	store := stubLoginStore(t)
	store.sessions[testLoginSession] = managedSession(t, time.Now().Add(-time.Minute), "OLD")
	stubSigninClient(t, &fakeTokenClient{t: t, err: errors.New("dial tcp: connection refused")})
	calls := stubLogin(t, nil)

	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	assert.Contains(t, err.Error(), "cache clear --storage login-session")
	assert.Empty(t, *calls)
	assert.Equal(t, "OLD", store.sessions[testLoginSession].AccessToken.AccessKeyID, "stored session untouched")
}

func TestManagedLogin_StoreErrorIsReported(t *testing.T) {
	p := loadTestProfile(t, "managed-login")
	store := stubLoginStore(t)
	store.getErr = errors.New("keychain locked")
	failIfLoginRuns(t)

	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keychain locked")
}

func TestManagedLogin_ChainedRole(t *testing.T) {
	p := loadTestProfile(t, "managed-role")
	store := stubLoginStore(t)
	store.sessions[testLoginSession] = managedSession(t, time.Now().Add(10*time.Minute), "ROOTKEY")
	stubSigninClient(t, &fakeTokenClient{t: t})
	failIfLoginRuns(t)
	sts := stubAssumeRole(t)

	creds, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{Duration: time.Hour})
	require.NoError(t, err)
	assert.Equal(t, "ROLEKEY", creds.AccessKeyID)
	assert.Equal(t, "ROOTKEY", sts.sourceCreds.AccessKeyID, "role assumed with the login session's credentials")
	assert.Equal(t, testLoginRoleARN, *sts.in.RoleArn)
}

func TestLoginRefreshError(t *testing.T) {
	assert.True(t, loginErrNeedsReauth(loginRefreshError(&signintypes.AccessDeniedException{Error_: signintypes.OAuth2ErrorCodeTokenExpired})))
	assert.True(t, loginErrNeedsReauth(loginRefreshError(&signintypes.AccessDeniedException{Error_: signintypes.OAuth2ErrorCodeUserCredentialsChanged})))
	assert.False(t, loginErrNeedsReauth(loginRefreshError(&signintypes.AccessDeniedException{Error_: signintypes.OAuth2ErrorCodeInsufficientPermissions})))
	plain := errors.New("boom")
	assert.Same(t, plain, loginRefreshError(plain))
}

func TestDescribeLoginSession(t *testing.T) {
	account, principal := describeLoginSession("arn:aws:iam::123456789012:user/alice")
	assert.Equal(t, "123456789012", account)
	assert.Equal(t, "user/alice", principal)

	account, principal = describeLoginSession("arn:aws:iam::123456789012:root")
	assert.Equal(t, "123456789012", account)
	assert.Equal(t, "root", principal)

	account, principal = describeLoginSession("not-an-arn")
	assert.Empty(t, account)
	assert.Empty(t, principal)
}

func TestSweepLoginTempDirs(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "login-old")
	fresh := filepath.Join(root, "login-fresh")
	require.NoError(t, os.MkdirAll(filepath.Join(old, "cache"), 0700))
	require.NoError(t, os.MkdirAll(filepath.Join(fresh, "cache"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(old, "cache", "x.json"), []byte("{}"), 0600))
	stale := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(old, stale, stale))

	sweepLoginTempDirs(root)

	_, err := os.Stat(old)
	assert.True(t, os.IsNotExist(err), "stale capture dir removed")
	_, err = os.Stat(fresh)
	assert.NoError(t, err, "recent capture dir kept")

	// A missing root is not an error.
	sweepLoginTempDirs(filepath.Join(root, "missing"))
}

func TestMakeDPoP(t *testing.T) {
	keyPEM := testDPOPKeyPEM(t)
	key, err := parseDPoPKey(keyPEM)
	require.NoError(t, err)
	now := time.Unix(1_800_000_000, 0)

	proof, err := makeDPoP(keyPEM, "POST", "https://ap-southeast-2.signin.aws.amazon.com/v1/token", now)
	require.NoError(t, err)
	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3)

	var header struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Jwk struct {
			Kty, Crv, X, Y string
		} `json:"jwk"`
	}
	decode := func(s string, v any) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(b, v))
	}
	decode(parts[0], &header)
	assert.Equal(t, "dpop+jwt", header.Typ)
	assert.Equal(t, "ES256", header.Alg)
	assert.Equal(t, "EC", header.Jwk.Kty)
	assert.Equal(t, "P-256", header.Jwk.Crv)
	x, err := base64.RawURLEncoding.DecodeString(header.Jwk.X)
	require.NoError(t, err)
	y, err := base64.RawURLEncoding.DecodeString(header.Jwk.Y)
	require.NoError(t, err)
	assert.Len(t, x, 32)
	assert.Len(t, y, 32)
	assert.Equal(t, 0, key.X.Cmp(new(big.Int).SetBytes(x)))
	assert.Equal(t, 0, key.Y.Cmp(new(big.Int).SetBytes(y)))

	var payload struct {
		Jti string `json:"jti"`
		Htm string `json:"htm"`
		Htu string `json:"htu"`
		Iat int64  `json:"iat"`
	}
	decode(parts[1], &payload)
	assert.NotEmpty(t, payload.Jti)
	assert.Equal(t, "POST", payload.Htm)
	assert.Equal(t, "https://ap-southeast-2.signin.aws.amazon.com/v1/token", payload.Htu)
	assert.Equal(t, now.Unix(), payload.Iat)

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, sig, 64)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	assert.True(t, ecdsa.Verify(&key.PublicKey, digest[:], r, s), "signature verifies with the session key")

	second, err := makeDPoP(keyPEM, "POST", "https://example.invalid/v1/token", now)
	require.NoError(t, err)
	assert.NotEqual(t, proof, second, "each proof carries a fresh jti")

	_, err = makeDPoP("not a key", "POST", "https://example.invalid", now)
	assert.Error(t, err)
}

func TestLoginSessionJSONMatchesCLIFormat(t *testing.T) {
	// A file written by `aws login` must unmarshal into the stored shape unchanged.
	dir := t.TempDir()
	path := writeLoginTokenAt(t, dir, testLoginSession, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "AKID")
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var tok securestorage.LoginSession
	require.NoError(t, json.Unmarshal(data, &tok))
	require.NoError(t, tok.Validate())
	assert.Equal(t, "AKID", tok.AccessToken.AccessKeyID)
	assert.Equal(t, "123456789012", tok.AccessToken.AccountID)
	assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), tok.AccessToken.ExpiresAt)
	assert.Equal(t, "REFRESH", tok.RefreshToken)
	assert.NotEmpty(t, tok.DPOPKey)

	creds := tok.Credentials()
	assert.Equal(t, "AKID", creds.AccessKeyID)
	assert.True(t, creds.CanExpire)
}
