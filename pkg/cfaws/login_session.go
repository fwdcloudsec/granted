package cfaws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/logincreds"
	"github.com/aws/aws-sdk-go-v2/service/signin"
	signintypes "github.com/aws/aws-sdk-go-v2/service/signin/types"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/internal/build"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
)

// GrantedLoginSessionKey is the profile key that marks an `aws login` session managed
// by Granted. Its value is the IAM principal ARN the session belongs to, the same value
// the AWS CLI writes as `login_session`. Granted keeps the session in secure storage
// instead of the CLI's plaintext cache, and serves it to the CLI through
// `credential_process`.
const GrantedLoginSessionKey = "granted_login_session"

// loginRefreshWindow is how close to expiry a managed session's access token may get
// before Granted refreshes it. The AWS CLI uses the same five minute threshold.
const loginRefreshWindow = 5 * time.Minute

// loginTempMaxAge is how long a capture directory may exist before the sweep treats
// it as an orphan from a crashed or killed process. A login that takes longer than
// this has already been abandoned by the user.
const loginTempMaxAge = time.Hour

// loginSessionStore is the subset of securestorage.LoginSessionSecureStorage the
// assumer uses, so tests can substitute an in-memory store.
type loginSessionStore interface {
	GetSession(session string) (*securestorage.LoginSession, error)
	StoreSession(session string, t securestorage.LoginSession) error
	ClearSession(session string) error
}

// Seams for tests. Production code uses the defaults.
var (
	newLoginSessionStore = func() loginSessionStore {
		s := securestorage.NewSecureLoginSessionStorage()
		return &s
	}
	// loginTempRoot is the parent of the throwaway directories `aws login` writes into.
	// It lives in Granted's own state folder so a sweep can safely remove leftovers.
	loginTempRoot = func() (string, error) {
		dir, err := grantedConfig.GrantedStateFolder()
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "login-tmp"), nil
	}
	loginNow = time.Now
)

// IsManagedLoginProfile reports whether the profile declares a Granted-managed
// `aws login` session (a `granted_login_session` key).
func IsManagedLoginProfile(p *Profile) bool {
	return p != nil && p.RawConfig != nil && p.RawConfig.HasKey(GrantedLoginSessionKey)
}

// IsLoginRootProfile reports whether the profile is an `aws login` session itself,
// rather than a role chained from one. Its credentials come straight from the
// session's own store and last 15 minutes.
func IsLoginRootProfile(p *Profile) bool {
	return p != nil && p.ProfileType == ProfileTypeAWSLogin && len(p.Parents) == 0
}

// loginSessionARN returns the session identifier the profile declares: the
// `granted_login_session` value for managed profiles, else the SDK-parsed `login_session`.
func loginSessionARN(p *Profile) string {
	if IsManagedLoginProfile(p) {
		return p.RawConfig.Key(GrantedLoginSessionKey).String()
	}
	return p.AWSConfig.LoginSession
}

// loadManagedLoginCreds returns credentials for a Granted-managed login profile from
// secure storage, refreshing the access token when it is close to expiry and running
// `aws login` when there is no usable session.
func loadManagedLoginCreds(ctx context.Context, root *Profile, configOpts ConfigOpts) (aws.Credentials, error) {
	session := loginSessionARN(root)
	if session == "" {
		return aws.Credentials{}, fmt.Errorf("profile %s has an empty %s value", root.Name, GrantedLoginSessionKey)
	}
	store := newLoginSessionStore()

	tok, err := store.GetSession(session)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("loading login session for profile %s from secure storage: %w", root.Name, err)
	}
	if tok != nil {
		creds, err := managedLoginCredentials(ctx, root, session, tok, store)
		if err == nil {
			return creds, nil
		}
		if !loginErrNeedsReauth(err) {
			return aws.Credentials{}, fmt.Errorf("failed to refresh login session for profile %s: %w. If the stored session is corrupt, run '%s cache clear --storage login-session' and then 'assume %s'", root.Name, err, build.GrantedBinaryName(), root.Name)
		}
		clio.Debugw("login session requires reauthentication", "profile", root.Name, "error", err)
	} else {
		clio.Debugw("no login session in secure storage", "profile", root.Name, "session", session)
	}

	if configOpts.UsingCredentialProcess && !configOpts.CredentialProcessAutoLogin {
		return aws.Credentials{}, fmt.Errorf("error when retrieving credentials from custom process. please login using 'assume %s'", root.Name)
	}

	captured, err := captureLoginSession(ctx, root, session, configOpts)
	if err != nil {
		return aws.Credentials{}, err
	}
	if err := store.StoreSession(session, *captured); err != nil {
		return aws.Credentials{}, fmt.Errorf("storing login session for profile %s in secure storage: %w", root.Name, err)
	}
	clio.Debugw("stored login session in secure storage", "profile", root.Name, "session", session, "expires", captured.AccessToken.ExpiresAt)
	return captured.Credentials(), nil
}

// managedLoginCredentials returns the stored session's credentials, refreshing them
// first if the access token is within loginRefreshWindow of expiry.
func managedLoginCredentials(ctx context.Context, root *Profile, session string, tok *securestorage.LoginSession, store loginSessionStore) (aws.Credentials, error) {
	if err := tok.Validate(); err != nil {
		return aws.Credentials{}, fmt.Errorf("stored login session is incomplete: %w", err)
	}
	if loginNow().Add(loginRefreshWindow).Before(tok.AccessToken.ExpiresAt) {
		return tok.Credentials(), nil
	}

	region := tok.SignInRegion
	if region == "" {
		var err error
		region, err = root.Region(ctx)
		if err != nil {
			return aws.Credentials{}, err
		}
	}
	clio.Debugw("refreshing login session", "profile", root.Name, "region", region, "expires", tok.AccessToken.ExpiresAt)

	refreshed, err := refreshLoginSession(ctx, newSigninTokenClient(region), tok)
	if err != nil {
		return aws.Credentials{}, err
	}
	if err := store.StoreSession(session, *refreshed); err != nil {
		return aws.Credentials{}, fmt.Errorf("storing refreshed login session in secure storage: %w", err)
	}
	return refreshed.Credentials(), nil
}

// refreshLoginSession exchanges the session's refresh token for a new access token,
// proving possession of the session key with a DPoP header. The returned session
// carries the new access token and, when the service rotates it, the new refresh token.
func refreshLoginSession(ctx context.Context, client logincreds.TokenAPIClient, tok *securestorage.LoginSession) (*securestorage.LoginSession, error) {
	out, err := client.CreateOAuth2Token(ctx, &signin.CreateOAuth2TokenInput{
		TokenInput: &signintypes.CreateOAuth2TokenRequestBody{
			ClientId:     aws.String(tok.ClientID),
			GrantType:    aws.String("refresh_token"),
			RefreshToken: aws.String(tok.RefreshToken),
		},
	}, withDPoP(tok.DPOPKey))
	if err != nil {
		return nil, fmt.Errorf("create oauth2 token: %w", loginRefreshError(err))
	}
	if out == nil || out.TokenOutput == nil || out.TokenOutput.AccessToken == nil || out.TokenOutput.ExpiresIn == nil {
		return nil, errors.New("create oauth2 token: response is missing the access token")
	}

	updated := *tok
	updated.AccessToken.AccessKeyID = aws.ToString(out.TokenOutput.AccessToken.AccessKeyId)
	updated.AccessToken.SecretAccessKey = aws.ToString(out.TokenOutput.AccessToken.SecretAccessKey)
	updated.AccessToken.SessionToken = aws.ToString(out.TokenOutput.AccessToken.SessionToken)
	updated.AccessToken.ExpiresAt = loginNow().Add(time.Duration(*out.TokenOutput.ExpiresIn) * time.Second).UTC()
	if rt := aws.ToString(out.TokenOutput.RefreshToken); rt != "" {
		updated.RefreshToken = rt
	}
	if tt := aws.ToString(out.TokenOutput.TokenType); tt != "" {
		updated.TokenType = tt
	}
	if err := updated.Validate(); err != nil {
		return nil, fmt.Errorf("refreshed login session is incomplete: %w", err)
	}
	return &updated, nil
}

// loginRefreshError maps the service's access-denied codes to the same messages the
// SDK's logincreds provider uses, so loginErrNeedsReauth treats both paths alike.
func loginRefreshError(err error) error {
	var denied *signintypes.AccessDeniedException
	if !errors.As(err, &denied) {
		return err
	}
	switch denied.Error_ {
	case signintypes.OAuth2ErrorCodeTokenExpired:
		return errors.New("login session has expired, please reauthenticate")
	case signintypes.OAuth2ErrorCodeUserCredentialsChanged:
		return errors.New("login session password has changed, please reauthenticate")
	case signintypes.OAuth2ErrorCodeInsufficientPermissions:
		return errors.New("insufficient permissions, you may be missing permissions for the CreateOAuth2Token action")
	default:
		return err
	}
}

// captureLoginSession runs `aws login` for the profile with the CLI's config and cache
// redirected into a private temporary directory, reads the session the CLI wrote,
// and removes the directory. The session never reaches the CLI's own cache.
//
// The scratch profile is pre-marked with the declared session ARN, so the CLI itself
// prompts if the browser signs in as someone else; whatever the user answers, a
// session for a different identity is never accepted.
func captureLoginSession(ctx context.Context, root *Profile, session string, configOpts ConfigOpts) (*securestorage.LoginSession, error) {
	region, err := root.Region(ctx)
	if err != nil {
		return nil, err
	}

	tmpRoot, err := loginTempRoot()
	if err != nil {
		return nil, err
	}
	sweepLoginTempDirs(tmpRoot)
	if err := os.MkdirAll(tmpRoot, 0700); err != nil {
		return nil, fmt.Errorf("creating login temp folder: %w", err)
	}
	tmp, err := os.MkdirTemp(tmpRoot, "login-")
	if err != nil {
		return nil, fmt.Errorf("creating login temp folder: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tmp); err != nil {
			clio.Warnf("failed to remove aws login temp folder %s: %s", tmp, err)
		}
	}()

	// An interrupt must still remove the directory: cancel the context so the child
	// is killed and the deferred cleanup runs.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cacheDir := filepath.Join(tmp, "cache")
	configFile := filepath.Join(tmp, "config")
	section := "profile " + root.Name
	if root.Name == "default" {
		section = "default"
	}
	scratch := fmt.Sprintf("[%s]\nlogin_session = %s\nregion = %s\n", section, session, region)
	if err := os.WriteFile(configFile, []byte(scratch), 0600); err != nil {
		return nil, fmt.Errorf("writing scratch config for aws login: %w", err)
	}

	env := []string{
		"AWS_CONFIG_FILE=" + configFile,
		"AWS_SHARED_CREDENTIALS_FILE=" + filepath.Join(tmp, "credentials"),
		"AWS_LOGIN_CACHE_DIRECTORY=" + cacheDir,
	}
	printLoginIdentityHint(root.Name, session)

	remote := configOpts.UseDeviceCode || isHeadlessEnvironment()
	if err := loginCommand(ctx, root.Name, remote, configOpts.Args, env); err != nil {
		return nil, err
	}

	path, err := logincreds.StandardCachedTokenFilepath(session, cacheDir)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("'aws login' finished but did not create a session for %s. The browser probably signed in as a different identity than profile %s declares; sign out of the AWS console (or use a browser profile for this identity) and run 'assume %s' again", session, root.Name, root.Name)
	}
	if err != nil {
		return nil, fmt.Errorf("reading the session written by aws login: %w", err)
	}

	var tok securestorage.LoginSession
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, fmt.Errorf("parsing the session written by aws login: %w", err)
	}
	if err := tok.Validate(); err != nil {
		return nil, fmt.Errorf("the session written by aws login is incomplete: %w", err)
	}
	if tok.SignInRegion == "" {
		tok.SignInRegion = region
	}
	return &tok, nil
}

// printLoginIdentityHint tells the user which identity the browser must sign in as.
// `aws login` takes whatever identity the browser already holds, and Granted rejects
// any other, so this is the one moment the user can steer the outcome.
func printLoginIdentityHint(profileName, session string) {
	account, principal := describeLoginSession(session)
	if account != "" && principal != "" {
		clio.Infof("Profile %s is bound to %s in account %s. Sign in to the AWS console as that identity; if the browser is already signed in as someone else, choose 'Sign in to a new session' rather than continuing with the active one.", profileName, principal, account)
		return
	}
	clio.Infof("Profile %s is bound to %s. Sign in to the AWS console as that identity.", profileName, session)
}

// describeLoginSession splits an IAM principal ARN such as
// arn:aws:iam::123456789012:user/alice into its account and "user/alice" parts.
func describeLoginSession(session string) (account, principal string) {
	parts := strings.SplitN(session, ":", 6)
	if len(parts) != 6 {
		return "", ""
	}
	return parts[4], parts[5]
}

// sweepLoginTempDirs removes capture directories older than loginTempMaxAge. They
// only exist if a previous capture was killed before its cleanup ran.
func sweepLoginTempDirs(tmpRoot string) {
	entries, err := os.ReadDir(tmpRoot)
	if err != nil {
		return
	}
	cutoff := loginNow().Add(-loginTempMaxAge)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		p := filepath.Join(tmpRoot, e.Name())
		clio.Debugw("removing orphaned aws login temp folder", "path", p)
		if err := os.RemoveAll(p); err != nil {
			clio.Debugw("failed to remove orphaned aws login temp folder", "path", p, "error", err)
		}
	}
}
