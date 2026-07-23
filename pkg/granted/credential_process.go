package granted

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/pkg/errors"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/accessrequest"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	sethRetry "github.com/sethvargo/go-retry"
	"github.com/urfave/cli/v2"
)

// AWS Creds consumed by credential_process must adhere to this schema
// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
type awsCredsStdOut struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}

var CredentialProcess = cli.Command{
	Name:  "credential-process",
	Usage: "Exports AWS session credentials for use with AWS CLI credential_process",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "profile", Required: true},
		&cli.StringFlag{Name: "url"},
		&cli.DurationFlag{Name: "window", Value: 15 * time.Minute},
		&cli.BoolFlag{Name: "auto-login", Usage: "automatically open the configured browser to log in if needed"},
		&cli.BoolFlag{Name: "no-cache", Usage: "Disables caching of session credentials and forces a refresh", EnvVars: []string{"GRANTED_NO_CACHE"}},
	},
	Action: func(c *cli.Context) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		profileName := c.String("profile")
		autoLogin := c.Bool("auto-login") || cfg.CredentialProcessAutoLogin
		secureSessionCredentialStorage := securestorage.NewSecureSessionCredentialStorage()
		clio.Debugw("running credential process with config", "profile", profileName, "url", c.String("url"), "window", c.Duration("window"), "disableCredentialProcessCache", cfg.DisableCredentialProcessCache)

		cliNoCache := c.Bool("no-cache")
		useCache := !cfg.DisableCredentialProcessCache && !cliNoCache

		if useCache {
			cachedCreds, err := secureSessionCredentialStorage.GetCredentials(profileName)
			if err != nil {
				clio.Debugw("error loading cached credentials", "error", err, "profile", profileName)
			} else if cachedCreds == nil {
				clio.Debugw("refreshing credentials", "reason", "cachedCreds was nil")
			} else if cachedCreds.CanExpire && cachedCreds.Expires.Add(-c.Duration("window")).Before(time.Now()) {
				clio.Debugw("refreshing credentials", "reason", "credentials are expired")
			} else {
				clio.Debugw("credentials found in cache", "expires", cachedCreds.Expires.String(), "canExpire", cachedCreds.CanExpire, "timeNow", time.Now().String(), "refreshIfBeforeNow", cachedCreds.Expires.Add(-c.Duration("window")).String())
				return printCredentials(*cachedCreds)
			}
		}

		if !useCache {
			clio.Debugw("refreshing credentials", "reason", "credential process cache is disabled via config")
		}

		err = secureSessionCredentialStorage.SecureStorage.Clear(profileName)
		if err != nil {
			clio.Debugw("error clearing cached credentials", "error", err, "profile", profileName)
		}

		profiles, err := cfaws.LoadProfiles()
		if err != nil {
			return err
		}

		profile, err := profiles.LoadInitialisedProfile(c.Context, profileName)
		if err != nil {
			return err
		}

		duration := time.Hour
		if profile.AWSConfig.RoleDurationSeconds != nil {
			duration = *profile.AWSConfig.RoleDurationSeconds
		}

		credentials, err := profile.AssumeTerminal(c.Context, cfaws.ConfigOpts{Duration: duration, UsingCredentialProcess: true, CredentialProcessAutoLogin: autoLogin, UseAuthorizationCode: cfg.UseAuthorizationCode})
		if err != nil {
			clio.Debugw("initial assume failed, attempting retry with backoff", "error", err)

			// Retry with exponential backoff in case of transient errors
			b := sethRetry.NewFibonacci(time.Second)
			b = sethRetry.WithMaxDuration(time.Second*30, b)
			retryErr := sethRetry.Do(c.Context, b, func(ctx context.Context) (err error) {
				credentials, err = profile.AssumeTerminal(c.Context, cfaws.ConfigOpts{Duration: duration, UsingCredentialProcess: true, CredentialProcessAutoLogin: autoLogin})
				if err != nil {
					return sethRetry.RetryableError(err)
				}
				return nil
			})
			if retryErr != nil {
				clio.Debugw("could not assume role after retries, notifying user to try requesting access", "error", err)
				saveErr := accessrequest.Profile{Name: profileName}.Save()
				if saveErr != nil {
					return saveErr
				}
				return errors.New("You don't have access but you can request it with 'granted request latest'")
			}
		}
		if !cfg.DisableCredentialProcessCache {
			clio.Debugw("storing refreshed credentials in credential process cache", "expires", credentials.Expires.String(), "canExpire", credentials.CanExpire, "timeNow", time.Now().String())
			if err := secureSessionCredentialStorage.StoreCredentials(profileName, credentials); err != nil {
				return err
			}
		}

		return printCredentials(credentials)
	},
}

func printCredentials(creds aws.Credentials) error {
	out := awsCredsStdOut{
		Version:         1,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
	}
	if creds.CanExpire {
		out.Expiration = creds.Expires.Format(time.RFC3339)
	}

	jsonOut, err := json.Marshal(out)
	if err != nil {
		return errors.Wrap(err, "marshalling session credentials")
	}

	fmt.Println(string(jsonOut))
	return nil
}
