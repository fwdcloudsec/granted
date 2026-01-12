package cfaws

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/fwdcloudsec/granted/pkg/testable"
)

func TypeCredsToAwsCreds(c types.Credentials) aws.Credentials {
	return aws.Credentials{AccessKeyID: *c.AccessKeyId, SecretAccessKey: *c.SecretAccessKey, SessionToken: *c.SessionToken, CanExpire: true, Expires: *c.Expiration}
}
func TypeRoleCredsToAwsCreds(c ssotypes.RoleCredentials) aws.Credentials {
	return aws.Credentials{AccessKeyID: *c.AccessKeyId, SecretAccessKey: *c.SecretAccessKey, SessionToken: *c.SessionToken, CanExpire: true, Expires: time.UnixMilli(c.Expiration)}
}

// CredProv implements the aws.CredentialProvider interface
type CredProv struct{ aws.Credentials }

func (c *CredProv) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return c.Credentials, nil
}

// will attempt to get credentials from the environment first and if not found then try getting credentials from a credential process
func GetAWSCredentials(ctx context.Context) (*aws.Credentials, error) {
	//first try loading credentials from the environment
	creds := GetEnvCredentials(ctx)

	if creds.AccessKeyID != "" {
		return &creds, nil
	}

	//if unsuccessful try and get from the credential cache
	profileName := os.Getenv("AWS_PROFILE")

	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	secureSessionCredentialStorage := securestorage.NewSecureSessionCredentialStorage()

	// check if profile is set in the environment
	useCache := !cfg.DisableCredentialProcessCache

	if useCache {
		// try and look up session credentials from the secure storage cache.
		cachedCreds, err := secureSessionCredentialStorage.GetCredentials(profileName)
		if err != nil {
			return nil, err
		}

		return cachedCreds, nil
	}

	if !useCache {
		clio.Debugw("refreshing credentials", "reason", "credential process cache is disabled via config")
	}

	profiles, err := LoadProfiles()
	if err != nil {
		return nil, err
	}

	profile, err := profiles.LoadInitialisedProfile(ctx, profileName)
	if err != nil {
		return nil, err
	}

	duration := time.Hour
	if profile.AWSConfig.RoleDurationSeconds != nil {
		duration = *profile.AWSConfig.RoleDurationSeconds
	}

	credentials, err := profile.AssumeTerminal(ctx, ConfigOpts{Duration: duration, UsingCredentialProcess: true, CredentialProcessAutoLogin: true})
	if err != nil {
		return nil, err
	}
	if !cfg.DisableCredentialProcessCache {
		clio.Debugw("storing refreshed credentials in credential process cache", "expires", credentials.Expires.String(), "canExpire", credentials.CanExpire, "timeNow", time.Now().String())
		if err := secureSessionCredentialStorage.StoreCredentials(profileName, credentials); err != nil {
			return nil, err
		}
	}

	return &credentials, nil

}

// loads the environment variables and hydrates an aws.config if they are present
func GetEnvCredentials(ctx context.Context) aws.Credentials {
	return aws.Credentials{AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"), SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"), SessionToken: os.Getenv("AWS_SESSION_TOKEN")}
}

func GetCredentialsCreds(ctx context.Context, c *Profile) (aws.Credentials, error) {
	// check to see if the creds are already exported
	creds, _ := aws.NewCredentialsCache(&CredProv{Credentials: c.AWSConfig.Credentials}).Retrieve(ctx)

	// check creds are valid - return them if they are
	if creds.HasKeys() && !creds.Expired() {
		cfg := aws.NewConfig()
		cfg.Credentials = &CredProv{Credentials: c.AWSConfig.Credentials}
		client := sts.NewFromConfig(cfg.Copy())
		// the AWS SDK check for credential expiry doesn't actually check some credentials so we do this sts call to validate it
		_, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err == nil {
			return creds, nil
		}
	}
	return aws.Credentials{}, fmt.Errorf("creds invalid or expired")

}

func MfaTokenProvider() (string, error) {
	in := survey.Input{Message: "MFA Token"}
	var out string
	withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
	err := testable.AskOne(&in, &out, withStdio)
	return out, err
}
