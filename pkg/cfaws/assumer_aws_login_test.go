package cfaws

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/logincreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/signin"
	signintypes "github.com/aws/aws-sdk-go-v2/service/signin/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
)

// loginCacheToken mirrors the JSON written by `aws login` and read by logincreds.
type loginCacheToken struct {
	AccessToken struct {
		AccessKeyID     string    `json:"accessKeyId"`
		SecretAccessKey string    `json:"secretAccessKey"`
		SessionToken    string    `json:"sessionToken"`
		AccountID       string    `json:"accountId"`
		ExpiresAt       time.Time `json:"expiresAt"`
	} `json:"accessToken"`
	TokenType     string `json:"tokenType"`
	RefreshToken  string `json:"refreshToken"`
	IdentityToken string `json:"identityToken"`
	ClientID      string `json:"clientId"`
	DPOPKey       string `json:"dpopKey"`
}

func testDPOPKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// writeLoginToken writes a cached login token for the session into
// AWS_LOGIN_CACHE_DIRECTORY and returns its path.
func writeLoginToken(t *testing.T, session string, expiresAt time.Time, accessKeyID string) string {
	t.Helper()
	return writeLoginTokenAt(t, os.Getenv("AWS_LOGIN_CACHE_DIRECTORY"), session, expiresAt, accessKeyID)
}

// writeLoginTokenAt writes a cached login token for the session into dir, in the
// layout `aws login` uses, and returns its path.
func writeLoginTokenAt(t *testing.T, dir, session string, expiresAt time.Time, accessKeyID string) string {
	t.Helper()
	path, err := logincreds.StandardCachedTokenFilepath(session, dir)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))

	var tok loginCacheToken
	tok.AccessToken.AccessKeyID = accessKeyID
	tok.AccessToken.SecretAccessKey = "SECRET"
	tok.AccessToken.SessionToken = "SESSION"
	tok.AccessToken.AccountID = "123456789012"
	tok.AccessToken.ExpiresAt = expiresAt.UTC()
	tok.TokenType = "aws_sigv4"
	tok.RefreshToken = "REFRESH"
	tok.IdentityToken = "IDENTITY"
	tok.ClientID = "arn:aws:signin:::devtools/same-device"
	tok.DPOPKey = testDPOPKeyPEM(t)

	data, err := json.Marshal(tok)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

func readLoginToken(t *testing.T, path string) loginCacheToken {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var tok loginCacheToken
	require.NoError(t, json.Unmarshal(data, &tok))
	return tok
}

// fakeTokenClient stands in for the signin client used to refresh a session.
type fakeTokenClient struct {
	t        *testing.T
	out      *signin.CreateOAuth2TokenOutput
	err      error
	calls    int
	in       *signin.CreateOAuth2TokenInput
	optCount int
}

func (f *fakeTokenClient) CreateOAuth2Token(ctx context.Context, in *signin.CreateOAuth2TokenInput, opts ...func(*signin.Options)) (*signin.CreateOAuth2TokenOutput, error) {
	f.calls++
	f.in = in
	f.optCount = len(opts)
	if f.out == nil && f.err == nil {
		f.t.Fatal("CreateOAuth2Token called unexpectedly")
	}
	return f.out, f.err
}

func refreshedTokenOutput(accessKeyID string) *signin.CreateOAuth2TokenOutput {
	return &signin.CreateOAuth2TokenOutput{
		TokenOutput: &signintypes.CreateOAuth2TokenResponseBody{
			AccessToken: &signintypes.AccessToken{
				AccessKeyId:     aws.String(accessKeyID),
				SecretAccessKey: aws.String("NEWSECRET"),
				SessionToken:    aws.String("NEWSESSION"),
			},
			ExpiresIn:    aws.Int32(900),
			RefreshToken: aws.String("NEWREFRESH"),
			TokenType:    aws.String("aws_sigv4"),
		},
	}
}

// loginCall records one invocation of the stubbed `aws login`.
type loginCall struct {
	profile     string
	remote      bool
	passthrough []string
	env         []string
}

// envValue returns the value of key in a KEY=VALUE environment slice.
func envValue(env []string, key string) string {
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			return strings.TrimPrefix(kv, key+"=")
		}
	}
	return ""
}

// stubLogin replaces the aws login command for the duration of the test. onLogin is
// called on each invocation and may write a token to simulate a successful login.
func stubLogin(t *testing.T, onLogin func(call loginCall) error) *[]loginCall {
	t.Helper()
	stubHeadless(t, false)
	calls := &[]loginCall{}
	orig := loginCommand
	loginCommand = func(ctx context.Context, profileName string, remote bool, passthrough []string, extraEnv []string) error {
		call := loginCall{profile: profileName, remote: remote, passthrough: passthrough, env: extraEnv}
		*calls = append(*calls, call)
		if onLogin == nil {
			return nil
		}
		return onLogin(call)
	}
	t.Cleanup(func() { loginCommand = orig })
	return calls
}

// stubHeadless pins the headless-environment check so tests behave the same on a
// desktop and on a CI runner (which has no display and would otherwise force --remote).
func stubHeadless(t *testing.T, headless bool) {
	t.Helper()
	orig := isHeadlessEnvironment
	isHeadlessEnvironment = func() bool { return headless }
	t.Cleanup(func() { isHeadlessEnvironment = orig })
}

func stubSigninClient(t *testing.T, client logincreds.TokenAPIClient) {
	t.Helper()
	orig := newSigninTokenClient
	newSigninTokenClient = func(region string) logincreds.TokenAPIClient { return client }
	t.Cleanup(func() { newSigninTokenClient = orig })
}

// fakeAssumeRoleClient records the AssumeRole call made during role chaining.
type fakeAssumeRoleClient struct {
	sourceCreds aws.Credentials
	in          *sts.AssumeRoleInput
	out         *sts.AssumeRoleOutput
}

func (f *fakeAssumeRoleClient) AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, opts ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.in = in
	return f.out, nil
}

func stubAssumeRole(t *testing.T) *fakeAssumeRoleClient {
	t.Helper()
	expiry := time.Now().Add(time.Hour).UTC()
	f := &fakeAssumeRoleClient{out: &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("ROLEKEY"),
			SecretAccessKey: aws.String("ROLESECRET"),
			SessionToken:    aws.String("ROLESESSION"),
			Expiration:      &expiry,
		},
	}}
	orig := newAssumeRoleClient
	newAssumeRoleClient = func(creds aws.Credentials, region string) stscreds.AssumeRoleAPIClient {
		f.sourceCreds = creds
		return f
	}
	t.Cleanup(func() { newAssumeRoleClient = orig })
	return f
}

func failIfLoginRuns(t *testing.T) {
	t.Helper()
	stubLogin(t, func(call loginCall) error {
		t.Fatalf("aws login ran unexpectedly for profile %s", call.profile)
		return nil
	})
}

func TestAwsLoginAssumer_ProfileMatchesType(t *testing.T) {
	a := &AwsLoginAssumer{}
	assert.True(t, a.ProfileMatchesType(nil, config.SharedConfig{LoginSession: testLoginSession}))
	assert.False(t, a.ProfileMatchesType(nil, config.SharedConfig{}))

	managed := ini.Empty().Section("profile managed")
	managed.Key(GrantedLoginSessionKey).SetValue(testLoginSession)
	assert.True(t, a.ProfileMatchesType(managed, config.SharedConfig{}))
	assert.False(t, a.ProfileMatchesType(ini.Empty().Section("profile plain"), config.SharedConfig{}))
	assert.Equal(t, ProfileTypeAWSLogin, a.Type())
	assert.Same(t, AssumerFromType(ProfileTypeAWSLogin), assumers[4])
}

func TestLoadProfiles_LoginProfileTypes(t *testing.T) {
	ctx := context.Background()
	profiles := writeLoginFixtures(t)

	root, err := profiles.LoadInitialisedProfile(ctx, "login-prof")
	require.NoError(t, err)
	assert.Equal(t, ProfileTypeAWSLogin, root.ProfileType)

	child, err := profiles.LoadInitialisedProfile(ctx, "dev-role")
	require.NoError(t, err)
	assert.Equal(t, ProfileTypeAWSLogin, child.ProfileType)

	iam, err := profiles.LoadInitialisedProfile(ctx, "plain-iam")
	require.NoError(t, err)
	assert.Equal(t, "AWS_IAM", iam.ProfileType)
}

func TestLoginTokenPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AWS_LOGIN_CACHE_DIRECTORY", dir)

	sum := sha256.Sum256([]byte(testLoginSession))
	want := filepath.Join(dir, strings.ToLower(hex.EncodeToString(sum[:]))+".json")

	got, err := loginTokenPath(&Profile{AWSConfig: config.SharedConfig{LoginSession: testLoginSession}})
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestAssumeTerminal_UsesCachedToken(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	writeLoginToken(t, testLoginSession, time.Now().Add(10*time.Minute), "AKID")
	stubSigninClient(t, &fakeTokenClient{t: t})
	failIfLoginRuns(t)

	creds, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.NoError(t, err)
	assert.Equal(t, "AKID", creds.AccessKeyID)
	assert.Equal(t, logincreds.ProviderName, creds.Source)
	assert.Equal(t, "123456789012", creds.AccountID)
	assert.True(t, creds.CanExpire)
}

func TestAssumeTerminal_NoToken_NonInteractive(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	stubSigninClient(t, &fakeTokenClient{t: t})
	calls := stubLogin(t, nil)

	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{UsingCredentialProcess: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws login --profile login-prof")
	assert.Empty(t, *calls)
}

func TestAssumeTerminal_NoToken_RunsLogin(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	stubSigninClient(t, &fakeTokenClient{t: t})
	calls := stubLogin(t, func(call loginCall) error {
		writeLoginToken(t, testLoginSession, time.Now().Add(10*time.Minute), "FRESH")
		return nil
	})

	creds, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{Args: []string{"--redirect-port", "8080"}})
	require.NoError(t, err)
	assert.Equal(t, "FRESH", creds.AccessKeyID)
	require.Len(t, *calls, 1)
	assert.Equal(t, loginCall{profile: "login-prof", remote: false, passthrough: []string{"--redirect-port", "8080"}}, (*calls)[0])
}

func TestAssumeTerminal_NoToken_CredentialProcessAutoLogin(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	stubSigninClient(t, &fakeTokenClient{t: t})
	calls := stubLogin(t, func(call loginCall) error {
		writeLoginToken(t, testLoginSession, time.Now().Add(10*time.Minute), "FRESH")
		return nil
	})

	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{UsingCredentialProcess: true, CredentialProcessAutoLogin: true})
	require.NoError(t, err)
	assert.Len(t, *calls, 1)
}

func TestAssumeTerminal_Remote(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	stubSigninClient(t, &fakeTokenClient{t: t})
	calls := stubLogin(t, func(call loginCall) error {
		writeLoginToken(t, testLoginSession, time.Now().Add(10*time.Minute), "FRESH")
		return nil
	})

	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{UseDeviceCode: true})
	require.NoError(t, err)
	require.Len(t, *calls, 1)
	assert.True(t, (*calls)[0].remote)
}

func TestAssumeTerminal_HeadlessUsesRemote(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	stubSigninClient(t, &fakeTokenClient{t: t})
	calls := stubLogin(t, func(call loginCall) error {
		writeLoginToken(t, testLoginSession, time.Now().Add(10*time.Minute), "FRESH")
		return nil
	})
	stubHeadless(t, true)

	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.NoError(t, err)
	require.Len(t, *calls, 1)
	assert.True(t, (*calls)[0].remote)
}

func TestAssumeTerminal_LoginFails(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	stubSigninClient(t, &fakeTokenClient{t: t})
	stubLogin(t, func(call loginCall) error { return errors.New("browser closed") })

	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "browser closed")
}

func TestAssumeTerminal_ExpiredToken_RefreshOK(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	path := writeLoginToken(t, testLoginSession, time.Now().Add(-time.Minute), "OLD")
	client := &fakeTokenClient{t: t, out: refreshedTokenOutput("REFRESHED")}
	stubSigninClient(t, client)
	failIfLoginRuns(t)

	creds, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.NoError(t, err)
	assert.Equal(t, "REFRESHED", creds.AccessKeyID)
	assert.Equal(t, 1, client.calls)
	assert.Equal(t, "refresh_token", aws.ToString(client.in.TokenInput.GrantType))
	assert.Equal(t, "REFRESH", aws.ToString(client.in.TokenInput.RefreshToken))

	saved := readLoginToken(t, path)
	assert.Equal(t, "REFRESHED", saved.AccessToken.AccessKeyID)
	assert.Equal(t, "NEWREFRESH", saved.RefreshToken)
	assert.True(t, saved.AccessToken.ExpiresAt.After(time.Now()))
}

func TestAssumeTerminal_ExpiredToken_SessionExpired_TriggersLogin(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	writeLoginToken(t, testLoginSession, time.Now().Add(-time.Minute), "OLD")
	client := &fakeTokenClient{t: t, err: &signintypes.AccessDeniedException{Error_: signintypes.OAuth2ErrorCodeTokenExpired}}
	stubSigninClient(t, client)
	calls := stubLogin(t, func(call loginCall) error {
		// a successful login replaces the cache with an unexpired token
		writeLoginToken(t, testLoginSession, time.Now().Add(10*time.Minute), "FRESH")
		return nil
	})

	creds, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.NoError(t, err)
	assert.Equal(t, "FRESH", creds.AccessKeyID)
	assert.Len(t, *calls, 1)
	assert.Equal(t, 1, client.calls)
}

func TestAssumeTerminal_ExpiredToken_OtherError_NoLogin(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	writeLoginToken(t, testLoginSession, time.Now().Add(-time.Minute), "OLD")
	stubSigninClient(t, &fakeTokenClient{t: t, err: errors.New("dial tcp: connection refused")})
	calls := stubLogin(t, nil)

	_, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	assert.Contains(t, err.Error(), "aws logout --profile login-prof")
	assert.Empty(t, *calls)
}

func TestAssumeTerminal_CorruptToken_NoLogin(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	path, err := loginTokenPath(p)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0600))
	stubSigninClient(t, &fakeTokenClient{t: t})
	calls := stubLogin(t, nil)

	_, err = (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws logout --profile login-prof")
	assert.Empty(t, *calls)
}

func TestLoginErrNeedsReauth(t *testing.T) {
	assert.False(t, loginErrNeedsReauth(nil))
	assert.False(t, loginErrNeedsReauth(errors.New("validate login token: missing clientId")))
	assert.True(t, loginErrNeedsReauth(errors.New("load login token: token file not found, please reauthenticate")))
	assert.True(t, loginErrNeedsReauth(errors.New("create oauth2 token: login session has expired, please reauthenticate")))
}

func TestAssumeTerminal_ChainedRole(t *testing.T) {
	p := loadTestProfile(t, "dev-role")
	writeLoginToken(t, testLoginSession, time.Now().Add(10*time.Minute), "ROOTKEY")
	stubSigninClient(t, &fakeTokenClient{t: t})
	failIfLoginRuns(t)
	roleClient := stubAssumeRole(t)

	creds, err := (&AwsLoginAssumer{}).AssumeTerminal(context.Background(), p, ConfigOpts{Duration: 45 * time.Minute})
	require.NoError(t, err)
	assert.Equal(t, "ROLEKEY", creds.AccessKeyID)
	assert.True(t, creds.CanExpire)

	assert.Equal(t, "ROOTKEY", roleClient.sourceCreds.AccessKeyID)
	require.NotNil(t, roleClient.in)
	assert.Equal(t, testLoginRoleARN, aws.ToString(roleClient.in.RoleArn))
	assert.Equal(t, int32(45*60), aws.ToInt32(roleClient.in.DurationSeconds))
	assert.NotEmpty(t, aws.ToString(roleClient.in.RoleSessionName))
}

func TestAssumeConsole_DelegatesToTerminal(t *testing.T) {
	p := loadTestProfile(t, "login-prof")
	writeLoginToken(t, testLoginSession, time.Now().Add(10*time.Minute), "AKID")
	stubSigninClient(t, &fakeTokenClient{t: t})
	failIfLoginRuns(t)

	a := &AwsLoginAssumer{}
	terminal, err := a.AssumeTerminal(context.Background(), p, ConfigOpts{})
	require.NoError(t, err)
	console, err := a.AssumeConsole(context.Background(), p, ConfigOpts{})
	require.NoError(t, err)
	assert.Equal(t, terminal, console)
}
