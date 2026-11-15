package cfaws

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/logincreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/signin"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/internal/build"
	"github.com/fwdcloudsec/granted/pkg/idclogin"
	"gopkg.in/ini.v1"
)

// ProfileTypeAWSLogin identifies profiles created by `aws login` (AWS CLI 2.32.0 or later).
// Such profiles carry a `login_session` key and keep their session in the AWS CLI's
// login cache (~/.aws/login/cache by default).
const ProfileTypeAWSLogin = "AWS_LOGIN"

// AwsLoginAssumer implements Assumer for `aws login` sessions.
//
// Granted never performs the browser login itself; it shells out to `aws login`.
// Two profile shapes are supported:
//
//   - Granted-managed (`granted_login_session`): the session is captured from
//     `aws login` into secure storage, refreshed by Granted, and served to the CLI via
//     `credential_process`. Nothing is left in the CLI's plaintext cache.
//   - Native (`login_session`, written by `aws login` itself): Granted reads and
//     refreshes the CLI's cache file through the SDK's logincreds provider.
type AwsLoginAssumer struct{}

// Seams for tests. Production code uses the defaults.
var (
	// loginCommand runs the interactive `aws login` for the named profile. extraEnv is
	// appended to the environment of the child process.
	loginCommand = runAwsLogin
	// newSigninTokenClient builds the client used to refresh the cached session.
	newSigninTokenClient = func(region string) logincreds.TokenAPIClient {
		return signin.New(signin.Options{Region: region})
	}
	// newAssumeRoleClient builds the STS client used for role chaining.
	newAssumeRoleClient = func(creds aws.Credentials, region string) stscreds.AssumeRoleAPIClient {
		return sts.New(sts.Options{Credentials: aws.NewCredentialsCache(&CredProv{creds}), Region: region})
	}
	// isHeadlessEnvironment reports whether a local browser redirect is unlikely to work.
	isHeadlessEnvironment = idclogin.IsHeadlessEnvironment
)

func (a *AwsLoginAssumer) AssumeTerminal(ctx context.Context, c *Profile, configOpts ConfigOpts) (aws.Credentials, error) {
	root := c
	if len(c.Parents) != 0 {
		root = c.Parents[0]
	}

	var creds aws.Credentials
	var err error
	if IsManagedLoginProfile(root) {
		creds, err = loadManagedLoginCreds(ctx, root, configOpts)
	} else {
		creds, err = loadLoginCreds(ctx, root, configOpts)
	}
	if err != nil {
		return aws.Credentials{}, err
	}
	if len(c.Parents) == 0 {
		return creds, nil
	}
	return assumeRoleChain(ctx, c, creds, configOpts)
}

// AssumeConsole returns the same credentials as AssumeTerminal. The federation
// endpoint accepts any session credentials, so no GetFederationToken call is needed.
func (a *AwsLoginAssumer) AssumeConsole(ctx context.Context, c *Profile, configOpts ConfigOpts) (aws.Credentials, error) {
	return a.AssumeTerminal(ctx, c, configOpts)
}

// A unique key which identifies this assumer e.g AWS-SSO or GOOGLE-AWS-AUTH
func (a *AwsLoginAssumer) Type() string {
	return ProfileTypeAWSLogin
}

// ProfileMatchesType matches profiles that declare an `aws login` session, either
// managed by Granted (granted_login_session) or by the AWS CLI (login_session).
func (a *AwsLoginAssumer) ProfileMatchesType(rawProfile *ini.Section, parsedProfile config.SharedConfig) bool {
	if rawProfile != nil && rawProfile.HasKey(GrantedLoginSessionKey) {
		return true
	}
	return parsedProfile.LoginSession != ""
}

// loginTokenPath returns the AWS CLI's cache file for the profile's login session,
// honouring AWS_LOGIN_CACHE_DIRECTORY like the SDK and CLI do.
func loginTokenPath(root *Profile) (string, error) {
	return logincreds.StandardCachedTokenFilepath(root.AWSConfig.LoginSession, os.Getenv("AWS_LOGIN_CACHE_DIRECTORY"))
}

// loadLoginCreds returns credentials for a native `aws login` profile from the CLI's
// cache file, running `aws login` first if the session is missing or needs
// reauthentication.
func loadLoginCreds(ctx context.Context, root *Profile, configOpts ConfigOpts) (aws.Credentials, error) {
	clio.Warnf("Profile %s keeps its aws login session unencrypted in the AWS CLI cache (~/.aws/login/cache)", root.Name)
	clio.Infof("To keep the session in secure storage instead, replace 'login_session' with '%s' and add 'credential_process = %s credential-process --profile=%s' to the profile", GrantedLoginSessionKey, build.GrantedBinaryName(), root.Name)

	path, err := loginTokenPath(root)
	if err != nil {
		return aws.Credentials{}, err
	}
	region, err := root.Region(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	provider := logincreds.New(newSigninTokenClient(region), path, func(o *logincreds.Options) {
		o.RestrictPermissions = true
	})

	needsLogin := false
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		clio.Debugw("aws login token not found", "profile", root.Name, "path", path)
		needsLogin = true
	} else {
		creds, err := provider.Retrieve(ctx)
		if err == nil {
			return creds, nil
		}
		if !loginErrNeedsReauth(err) {
			return aws.Credentials{}, fmt.Errorf("failed to load aws login session for profile %s: %w. If the cached session is corrupt, run 'aws logout --profile %s' and then 'aws login --profile %s'", root.Name, err, root.Name, root.Name)
		}
		clio.Debugw("aws login session requires reauthentication", "profile", root.Name, "error", err)
		needsLogin = true
	}

	if needsLogin {
		if configOpts.UsingCredentialProcess && !configOpts.CredentialProcessAutoLogin {
			return aws.Credentials{}, fmt.Errorf("error when retrieving credentials from custom process. please login using 'aws login --profile %s'", root.Name)
		}
		remote := configOpts.UseDeviceCode || isHeadlessEnvironment()
		if err := loginCommand(ctx, root.Name, remote, configOpts.Args, nil); err != nil {
			return aws.Credentials{}, err
		}
	}

	return provider.Retrieve(ctx)
}

// loginErrNeedsReauth reports whether a logincreds error means the user has to run
// `aws login` again (missing token file, expired session, changed password). The SDK
// exports no sentinel errors for these, so this matches the message text it uses;
// the coupling is pinned by tests.
func loginErrNeedsReauth(err error) bool {
	return err != nil && strings.Contains(err.Error(), "please reauthenticate")
}

// runAwsLogin runs `aws login --profile <name>` interactively. Its stdout is sent to
// stderr because the assume shell wrapper parses this process's stdout. extraEnv is
// appended to the inherited environment.
func runAwsLogin(ctx context.Context, profileName string, remote bool, passthrough []string, extraEnv []string) error {
	bin, err := exec.LookPath("aws")
	if err != nil {
		return fmt.Errorf("profile %s uses an 'aws login' session but the 'aws' CLI was not found on PATH. Install AWS CLI v2.32.0 or later and run 'aws login --profile %s'", profileName, profileName)
	}

	args := []string{"login", "--profile", profileName}
	if remote {
		args = append(args, "--remote")
	}
	args = append(args, passthrough...)

	clio.Infof("No valid aws login session for profile %s, running 'aws %s'", profileName, strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if len(extraEnv) != 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("'aws login --profile %s' failed: %w (requires AWS CLI v2.32.0 or later)", profileName, err)
	}
	return nil
}

// assumeRoleChain assumes each profile in c.Parents[1:] and then c itself, starting
// from the root credentials. The behaviour mirrors the chaining in
// CredentialProcessAssumer.AssumeTerminal.
func assumeRoleChain(ctx context.Context, c *Profile, rootCreds aws.Credentials, configOpts ConfigOpts) (aws.Credentials, error) {
	creds := rootCreds
	for _, p := range c.Parents[1:] {
		region, err := p.Region(ctx)
		if err != nil {
			return aws.Credentials{}, err
		}
		stsp := stscreds.NewAssumeRoleProvider(newAssumeRoleClient(creds, region), p.AWSConfig.RoleARN, func(aro *stscreds.AssumeRoleOptions) {
			if p.AWSConfig.RoleSessionName != "" {
				aro.RoleSessionName = p.AWSConfig.RoleSessionName
			} else {
				aro.RoleSessionName = sessionName()
			}
			if p.AWSConfig.MFASerial != "" {
				aro.SerialNumber = &p.AWSConfig.MFASerial
				aro.TokenProvider = mfaTokenProviderFor(configOpts)
			} else if c.AWSConfig.MFASerial != "" {
				aro.SerialNumber = &c.AWSConfig.MFASerial
				aro.TokenProvider = mfaTokenProviderFor(configOpts)
			}
			aro.Duration = configOpts.Duration
		})
		creds, err = stsp.Retrieve(ctx)
		if err != nil {
			return creds, err
		}
	}

	region, err := c.Region(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	stsp := stscreds.NewAssumeRoleProvider(newAssumeRoleClient(creds, region), c.AWSConfig.RoleARN, func(aro *stscreds.AssumeRoleOptions) {
		aro.RoleSessionName = getRoleSessionNameFromProfile(c)
		if c.AWSConfig.MFASerial != "" {
			aro.SerialNumber = &c.AWSConfig.MFASerial
			aro.TokenProvider = mfaTokenProviderFor(configOpts)
		}
		aro.Duration = configOpts.Duration
		if c.AWSConfig.ExternalID != "" {
			aro.ExternalID = &c.AWSConfig.ExternalID
		}
	})
	return stsp.Retrieve(ctx)
}

// mfaTokenProviderFor returns a token provider that uses the code passed on the
// command line when one was given, and prompts otherwise.
func mfaTokenProviderFor(configOpts ConfigOpts) func() (string, error) {
	if configOpts.MFATokenCode != "" {
		return func() (string, error) {
			return configOpts.MFATokenCode, nil
		}
	}
	return MfaTokenProvider
}
