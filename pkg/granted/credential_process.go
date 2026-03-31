package granted

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/pkg/errors"

	"github.com/common-fate/clio"
	"github.com/common-fate/grab"
	"github.com/common-fate/sdk/eid"
	accessv1alpha1 "github.com/common-fate/sdk/gen/commonfate/access/v1alpha1"
	"github.com/common-fate/sdk/service/access/grants"
	identitysvc "github.com/common-fate/sdk/service/identity"
	"github.com/fwdcloudsec/granted/pkg/accessrequest"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/fwdcloudsec/granted/pkg/cfcfg"
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
			// try and look up session credentials from the secure storage cache.
			cachedCreds, err := secureSessionCredentialStorage.GetCredentials(profileName)
			if err != nil {
				clio.Debugw("error loading cached credentials", "error", err, "profile", profileName)
			} else if cachedCreds == nil {
				clio.Debugw("refreshing credentials", "reason", "cachedCreds was nil")
			} else if cachedCreds.CanExpire && cachedCreds.Expires.Add(-c.Duration("window")).Before(time.Now()) {
				clio.Debugw("refreshing credentials", "reason", "credentials are expired")
			} else {
				// if we get here, the cached session credentials are valid
				clio.Debugw("credentials found in cache", "expires", cachedCreds.Expires.String(), "canExpire", cachedCreds.CanExpire, "timeNow", time.Now().String(), "refreshIfBeforeNow", cachedCreds.Expires.Add(-c.Duration("window")).String())
				return printCredentials(*cachedCreds)
			}
		}

		if !useCache {
			clio.Debugw("refreshing credentials", "reason", "credential process cache is disabled via config")
		}

		// purge the credentials from the cache
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
			// We first check if there was an active grant for this profile, and if there was, allow 30s of retries before bailing out
			cfg, cfConfigErr := cfcfg.Load(c.Context, profile)
			if cfConfigErr != nil {
				clio.Debugw("failed to load cfconfig, skipping check for active grants in a common fate deployment", "error", cfConfigErr)
				return err
			}

			grantsClient := grants.NewFromConfig(cfg)
			idClient := identitysvc.NewFromConfig(cfg)
			callerID, callerIDErr := idClient.GetCallerIdentity(c.Context, connect.NewRequest(&accessv1alpha1.GetCallerIdentityRequest{}))
			if callerIDErr != nil {
				clio.Debugw("failed to load caller identity for user", "error", callerIDErr)
				// return the original error
				return err
			}
			grants, queryGrantsErr := grab.AllPages(c.Context, func(ctx context.Context, nextToken *string) ([]*accessv1alpha1.Grant, *string, error) {
				grants, err := grantsClient.QueryGrants(c.Context, connect.NewRequest(&accessv1alpha1.QueryGrantsRequest{
					Principal: callerID.Msg.Principal.Eid,
					Target:    eid.New("AWS::Account", profile.AWSConfig.SSOAccountID).ToAPI(),
					// This API needs to be updated to use specifiers, for now, fetch all active grants and check for a match on the role name
					// Role:      eid.New("AWS::Account", profile.AWSConfig.SSOAccountID).ToAPI(),
					Status: accessv1alpha1.GrantStatus_GRANT_STATUS_ACTIVE.Enum(),
				}))
				if err != nil {
					return nil, nil, err
				}
				return grants.Msg.Grants, &grants.Msg.NextPageToken, nil
			})

			if queryGrantsErr != nil {
				clio.Debugw("failed to query for active grants", "error", queryGrantsErr)
				// return the original error
				return err
			}

			var foundActiveGrant bool
			for _, grant := range grants {
				if grant.Role.Name == profile.AWSConfig.SSORoleName {
					clio.Debugw("found active grant matching the profile, will retry assuming role", "grant", grant)
					foundActiveGrant = true
					break
				}
			}
			if !foundActiveGrant {
				clio.Debug("did not find any matching active grants for the profile, will not retry assuming role")
				clio.Debugw("could not assume role due to the following error, notifying user to try requesting access", "error", err)
				err := accessrequest.Profile{Name: profileName}.Save()
				if err != nil {
					return err
				}
				return errors.New("You don't have access but you can request it with 'granted request latest'")
			}

			// there is an active grant so retry assuming because the error may be transient
			b := sethRetry.NewFibonacci(time.Second)
			b = sethRetry.WithMaxDuration(time.Second*30, b)
			err = sethRetry.Do(c.Context, b, func(ctx context.Context) (err error) {
				credentials, err = profile.AssumeTerminal(c.Context, cfaws.ConfigOpts{Duration: duration, UsingCredentialProcess: true, CredentialProcessAutoLogin: autoLogin})
				if err != nil {
					return sethRetry.RetryableError(err)
				}
				return nil
			})
			if err != nil {
				return err
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
