package doctor

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/assume"
	"github.com/fwdcloudsec/granted/pkg/browser"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/urfave/cli/v2"
)

var Command = cli.Command{
	Name:        "doctor",
	Usage:       "Run diagnostics locally to help debug common issues relating to granted and aws",
	Subcommands: []*cli.Command{},
	Action:      DoctorCommand,
	Flags: []cli.Flag{&cli.StringFlag{
		Name: "profile",
	}},
}

type GrantedDoctor struct {
	ProfileName string
	Profile     cfaws.Profile
	Profiles    *cfaws.Profiles
	Cfg         *grantedConfig.Config
}

func DoctorCommand(c *cli.Context) error {
	clio.NewLine()

	clio.Info("Checking your Granted and AWS local configurations to look for common issues...\n")

	ctx := c.Context

	cfg, err := grantedConfig.Load()
	if err != nil {
		return err
	}
	profileName := c.String("profile")

	profiles, err := cfaws.LoadProfiles()
	if err != nil {
		return err
	}

	if profileName == "" {
		// ask for a profile to test against
		profileName, err = assume.QueryProfiles(profiles)
		if err != nil {
			return err
		}
	}

	profile, err := profiles.LoadInitialisedProfile(ctx, profileName)
	if err != nil {
		return err
	}

	doctor := GrantedDoctor{
		ProfileName: profileName,
		Profiles:    profiles,
		Profile:     *profile,
		Cfg:         cfg,
	}

	clio.Infof("profile selected: %s\n", profile.Name)
	clio.Infof("profile SSO start URL: %s\n", profile.SSOStartURL())
	clio.Infof("profile region: %s\n", profile.AWSConfig.Region)

	clio.Info("Granted doctor will now check the default sso token cache (`~/.aws/sso/cache`), Granted secure storage, and the AWS credentials file to valiate cached tokens.")

	//search through and look for sources of sso tokens
	//search through all the aws/cache tokens first
	err = doctor.CheckAllAWSCacheTokens(ctx)
	if err != nil {
		return err
	}

	//search through all the aws/cache tokens first
	err = doctor.CheckAllAWSKeychainTokens(ctx)
	if err != nil {
		return err
	}

	err = doctor.CommonIssuesWarningMessages(ctx)
	if err != nil {
		return err
	}

	clio.NewLine()

	clio.Success("Granted Doctor has completed, see diagnostics above")

	return nil
}

func (d *GrantedDoctor) CheckAllAWSCacheTokens(ctx context.Context) error {
	if cfaws.SsoCredsAreInConfigCache() {
		clio.NewLine()

		clio.Info("Checking all cached credentials in `/.aws/sso/cache` \n")

		path, err := cfaws.GetDefaultCacheLocation()
		if err != nil {
			return err
		}
		// now open the folder
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		// now read the folder
		files, err := f.Readdir(-1)
		if err != nil {
			return err
		}
		// close the folder
		defer func() { _ = f.Close() }()

		if len(files) == 0 {
			clio.Info("No valid cached credentials found in `/.aws/sso/cache`")
		}

		for _, file := range files {
			// check if the file is a json file
			if filepath.Ext(file.Name()) == ".json" {
				// open the file
				f, err := os.Open(filepath.Join(path, file.Name()))
				if err != nil {
					return err
				}
				// read the file
				data, err := io.ReadAll(f)
				if err != nil {
					return err
				}

				// if file doesn't start with botocore
				if !strings.HasPrefix(file.Name(), "botocore") {
					// close the file
					defer func() { _ = f.Close() }()
					// unmarshal the json
					var cachedToken cfaws.SSOPlainTextOut
					err = json.Unmarshal(data, &cachedToken)
					if err != nil {
						return err
					}
					if d.Profile.SSOStartURL() != cachedToken.StartUrl {
						//not related to selected profile
						continue
					}
					expiry, err := time.Parse(time.RFC3339, cachedToken.ExpiresAt)
					if err != nil {
						return err
					}
					//if expired dont even try
					if expiry.Before(time.Now()) {
						clio.Warnf("[INFO] cached token for %s expired", cachedToken.StartUrl)
						continue
					}
					if cachedToken.AccessToken == "" {
						continue
					}
					if cachedToken.Region == "" {
						continue
					}

					//if we got here tell the user that we found a valid cached credential
					clio.Infof("cached token for %s is valid. Testing token using sts now...", cachedToken.StartUrl)
					err = d.CheckValidCredentials(ctx, cachedToken)
					if err != nil {
						return err
					}

				}
			}
		}
	}
	return nil

}

func (d *GrantedDoctor) CheckAllAWSKeychainTokens(ctx context.Context) error {
	clio.NewLine()
	clio.Info("Checking all cached tokens in secure storage \n")

	secureSSOTokenStorage := securestorage.NewSecureSSOTokenStorage()
	ssoTokenKey := d.Profile.SSOStartURL() + d.Profile.AWSConfig.SSOSessionName

	//This filters out any tokens that have expired
	cachedToken := secureSSOTokenStorage.GetValidSSOToken(ctx, ssoTokenKey)
	if cachedToken != nil {
		err := d.CheckValidCredentials(ctx, cfaws.SSOPlainTextOut{
			AccessToken: cachedToken.AccessToken,
			Region:      cachedToken.Region,
		})
		if err != nil {
			return err
		}
	}
	clio.Warn("[INFO] no cached tokens in secure storage found")

	return nil

}

func (d *GrantedDoctor) CheckValidCredentials(ctx context.Context, token cfaws.SSOPlainTextOut) error {
	secureSSOTokenStorage := securestorage.NewSecureSSOTokenStorage()

	cfg := aws.NewConfig()
	cfg.Region = d.Profile.SSORegion()
	creds, err := d.Profile.SSOLoginWithToken(ctx, cfg, &token.AccessToken, secureSSOTokenStorage, cfaws.ConfigOpts{})
	if _, ok := err.(cfaws.NoAccessError); ok {
		clio.Info("No access to current profile, skipping...\n")
		return nil
	}
	if err != nil {
		return err
	}
	stsConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(token.Region),
		config.WithCredentialsProvider(&ssoCredentialsProvider{creds: creds}),
	)
	if err != nil {
		return err
	}

	client := sts.NewFromConfig(stsConfig)

	input := &sts.GetCallerIdentityInput{}
	_, err = client.GetCallerIdentity(ctx, input)
	if err != nil {
		clio.Errorf("[FAILED] Credentials found for %s were not expired but failed sts api call", token.StartUrl)
		return nil

	}
	clio.NewLine()

	clio.Successf("[VALID] Credentials found for %s are still valid", token.StartUrl)
	return nil
}

// This method handles telling the user about some of the configurations they may have set and the potential for unintended outcomes as a result
func (d *GrantedDoctor) CommonIssuesWarningMessages(ctx context.Context) error {
	clio.NewLine()

	clio.Info("Checking commonly found issues in Granted configuration \n")

	// warn about any particular settings that are set
	if !d.Cfg.DefaultExportAllEnvVar {
		clio.Warn("[INFO] DefaultExportAllEnvVar set to false: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN variables will not be exported to your environment for profiles using credential process. Set this to true if you need this functionality")
	} else {
		clio.Warn("[INFO] DefaultExportAllEnvVar set to true. Automatic credential renewal is disabled.")
	}

	if d.Cfg.DefaultBrowser != browser.FirefoxKey {
		clio.Info("[RECOMMENDED] Not using Firefox as default browser, we recommend using Firefox to make use of the multi-account containers functionality with Granted.")
	}

	return nil

}

type ssoCredentialsProvider struct {
	creds aws.Credentials
}

func (p *ssoCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return p.creds, nil
}
