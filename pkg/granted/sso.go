package granted

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sync"

	"net/http"
	"os"
	"regexp"

	"github.com/AlecAivazis/survey/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/common-fate/awsconfigfile"
	"github.com/common-fate/clio"
	"github.com/common-fate/clio/clierr"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	grantedconfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/idclogin"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/fwdcloudsec/granted/pkg/testable"
	"github.com/schollz/progressbar/v3"
	"github.com/urfave/cli/v2"
	uberratelimit "go.uber.org/ratelimit"
	"golang.org/x/sync/errgroup"
	"gopkg.in/ini.v1"
)

var SSOCommand = cli.Command{
	Name:        "sso",
	Usage:       "Manage your local AWS configuration file from information available in AWS SSO",
	Subcommands: []*cli.Command{&GenerateCommand, &PopulateCommand, &LoginCommand},
}

const (
	// permission for user to read/write.
	USER_READ_WRITE_PERM = 0700
)

// in dev:
// go run ./cmd/granted/main.go sso generate --sso-region ap-southeast-2 [url]
var GenerateCommand = cli.Command{
	Name:      "generate",
	Usage:     "Prints an AWS configuration file to stdout with profiles from accounts and roles available in AWS SSO",
	UsageText: "granted [global options] sso generate [command options] [sso-start-url]",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "Specify the SSO config section in the Granted config file ([SSO.name])", Value: "default"},
		&cli.StringFlag{Name: "prefix", Usage: "Specify a prefix for all generated profile names"},
		&cli.StringFlag{Name: "sso-region", Usage: "Specify the SSO region"},
		&cli.StringSliceFlag{Name: "source", Usage: "The sources to load AWS profiles from (valid values are: 'aws-sso')", Value: cli.NewStringSlice("aws-sso")},
		&cli.BoolFlag{Name: "no-credential-process", Usage: "Generate profiles without the Granted credential-process integration"},
		&cli.StringFlag{Name: "profile-template", Usage: "Specify profile name template", Value: awsconfigfile.DefaultProfileNameTemplate}},
	Action: func(c *cli.Context) error {
		ctx := c.Context
		fullCommand := fmt.Sprintf("%s %s", c.App.Name, c.Command.FullName()) // e.g. 'granted sso populate'

		// load config to load defaults
		cfg, err := grantedconfig.Load()
		if err != nil {
			clio.Errorf("Error reading default config (~/.granted/config)")
			return nil
		}

		cfgSSO := cfg.SSO[c.String("config")]
		startURL := coalesceString(c.Args().First(), cfgSSO.StartURL)
		if startURL == "" {
			return clierr.New(fmt.Sprintf("Usage: %s [sso-start-url]", fullCommand), clierr.Infof("For example, %s https://example.awsapps.com/start", fullCommand))
		}

		// if --sso-region is not set, display that is it required
		ssoRegion := coalesceString(c.String("sso-region"), cfgSSO.SSORegion)
		if ssoRegion == "" {
			clio.Errorf("Please specify the --sso-region flag: '%s --sso-region us-east-1 %s'", fullCommand, startURL)
			return nil
		}

		// Since `profile-template` has a default value, need to check IsSet instead of having a value
		var profileNameTemplate string
		if c.IsSet("profile-template") {
			// when not set, use config when it has a value
			profileNameTemplate = c.String("profile-template")
		} else {
			// prefer config over default
			profileNameTemplate = coalesceString(cfgSSO.ProfileTemplate, c.String("profile-template"))
		}

		prefix := coalesceString(c.String("prefix"), cfgSSO.Prefix)
		noCredentialProcess := c.Bool("no-credential-process") || cfgSSO.NoCredentialProcess

		g := awsconfigfile.Generator{
			Config:              ini.Empty(),
			ProfileNameTemplate: profileNameTemplate,
			NoCredentialProcess: noCredentialProcess,
			Prefix:              prefix,
		}

		for _, s := range c.StringSlice("source") {
			switch s {
			case "aws-sso":
				g.AddSource(AWSSSOSource{SSORegion: ssoRegion, StartURL: startURL})
			case "commonfate", "common-fate", "cf":
				return fmt.Errorf("the common fate profile source is no longer supported: https://www.commonfate.io/blog/winding-down")
			default:
				return fmt.Errorf("unknown profile source %s: allowed sources are aws-sso", s)
			}
		}

		err = g.Generate(ctx)
		if err != nil {
			return err
		}

		_, err = g.Config.WriteTo(os.Stdout)
		if err != nil {
			return err
		}

		return nil
	},
}

var PopulateCommand = cli.Command{
	Name:      "populate",
	Usage:     "Populate your local AWS configuration file with profiles from accounts and roles available in AWS SSO",
	UsageText: "granted [global options] sso populate [command options] [sso-start-url]",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Usage: "Specify the SSO config section ([SSO.name])", Value: "default"},
		&cli.StringFlag{Name: "prefix", Usage: "Specify a prefix for all generated profile names"},
		&cli.StringFlag{Name: "sso-region", Usage: "Specify the SSO region"},
		&cli.StringSliceFlag{Name: "sso-scope", Usage: "Specify the SSO scopes"},
		&cli.StringSliceFlag{Name: "source", Usage: "The sources to load AWS profiles from", Value: cli.NewStringSlice("aws-sso")},
		&cli.BoolFlag{Name: "prune", Usage: "Remove any generated profiles with the 'common_fate_generated_from' key which no longer exist"},
		&cli.StringFlag{Name: "profile-template", Usage: "Specify profile name template", Value: awsconfigfile.DefaultProfileNameTemplate},
		&cli.BoolFlag{Name: "no-credential-process", Usage: "Generate profiles without the Granted credential-process integration"},
	},
	Action: func(c *cli.Context) error {
		ctx := c.Context
		fullCommand := fmt.Sprintf("%s %s", c.App.Name, c.Command.FullName()) // e.g. 'granted sso populate'

		cfg, err := grantedconfig.Load()
		if err != nil {
			clio.Errorf("Error reading default config (~/.granted/config)")
			return nil
		}

		cfgSSO := cfg.SSO[c.String("config")]

		startURL := coalesceString(c.Args().First(), cfgSSO.StartURL)
		if startURL == "" {
			return clierr.New(fmt.Sprintf("Usage: %s [sso-start-url]", fullCommand), clierr.Infof("For example, %s https://example.awsapps.com/start", fullCommand))
		}

		// if --sso-region is not set, display that is it required
		ssoRegion := coalesceString(c.String("sso-region"), cfgSSO.SSORegion)
		if ssoRegion == "" {
			clio.Errorf("Please specify the --sso-region flag: '%s --sso-region us-east-1 %s'", fullCommand, startURL)
			return nil
		}

		// Since `profile-template` has a default value, need to check IsSet instead of having a value
		var profileNameTemplate string
		if c.IsSet("profile-template") {
			// when not set, use config when it has a value
			profileNameTemplate = c.String("profile-template")
		} else {
			// prefer config over default
			profileNameTemplate = coalesceString(cfgSSO.ProfileTemplate, c.String("profile-template"))
		}

		prefix := coalesceString(c.String("prefix"), cfgSSO.Prefix)
		noCredentialProcess := c.Bool("no-credential-process") || cfgSSO.NoCredentialProcess

		configFilename := cfaws.GetAWSConfigPath()

		// Create ~/.aws if it does not exists
		dir := filepath.Dir(configFilename)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			clio.Infof("created AWS config file: %s", dir)
			err = os.MkdirAll(dir, USER_READ_WRITE_PERM)
			if err != nil {
				return err
			}
		}

		config, err := ini.LoadSources(ini.LoadOptions{
			AllowNonUniqueSections:  false,
			SkipUnrecognizableLines: false,
			AllowNestedValues:       true,
		}, configFilename)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			config = ini.Empty()
		}

		var pruneStartURLs []string

		if c.Bool("prune") {
			pruneStartURLs = []string{startURL}
		}

		g := awsconfigfile.Generator{
			Config:              config,
			ProfileNameTemplate: profileNameTemplate,
			NoCredentialProcess: noCredentialProcess,
			Prefix:              prefix,
			PruneStartURLs:      pruneStartURLs,
		}

		for _, s := range c.StringSlice("source") {
			switch s {
			case "aws-sso":
				g.AddSource(AWSSSOSource{SSORegion: ssoRegion, StartURL: startURL, SSOScopes: c.StringSlice("sso-scope")})
			case "commonfate", "common-fate", "cf":
				return fmt.Errorf("the common fate profile source is no longer supported: https://www.commonfate.io/blog/winding-down")
			default:
				return fmt.Errorf("unknown profile source %s: allowed sources are aws-sso", s)
			}
		}
		err = g.Generate(ctx)
		if err != nil {
			return err
		}

		err = config.SaveTo(configFilename)
		if err != nil {
			return err
		}

		return nil
	},
}

var LoginCommand = cli.Command{
	Name:  "login",
	Usage: "Log in via AWS SSO interactive credential process",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "sso-region", Usage: "Specify the SSO region"},
		&cli.StringFlag{Name: "sso-start-url", Usage: "Specify the SSO start url"},
		&cli.StringSliceFlag{Name: "sso-scope", Usage: "Specify the SSO scopes"},
	},
	Action: func(c *cli.Context) error {
		ctx := c.Context
		ssoStartUrl := c.String("sso-start-url")

		if ssoStartUrl == "" {
			in1 := survey.Input{Message: "SSO Start URL"}
			err := testable.AskOne(&in1, &ssoStartUrl)
			if err != nil {
				return err
			}
		}

		ssoRegion := c.String("sso-region")

		if ssoRegion == "" {
			// fetch the start url to extract the region from the html
			resp, err := http.Get(ssoStartUrl)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			// extract the region using a regex on the meta tag "region"
			re := regexp.MustCompile(`<meta\s+name="region"\s+content="(.*?)"/>`)
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			match := re.FindStringSubmatch(string(body))
			if len(match) == 2 {
				ssoRegion = match[1]
			}

			// Fallback to user input
			if ssoRegion == "" {
				in2 := survey.Input{Message: "Region"}
				err := testable.AskOne(&in2, &ssoRegion)
				if err != nil {
					return err
				}
			}
		}

		ssoScopes := c.StringSlice("sso-scope")

		cfg := aws.NewConfig()
		cfg.Region = ssoRegion

		secureSSOTokenStorage := securestorage.NewSecureSSOTokenStorage()

		newSSOToken, err := idclogin.Login(ctx, *cfg, ssoStartUrl, ssoScopes)
		if err != nil {
			return err
		}

		secureSSOTokenStorage.StoreSSOToken(ssoStartUrl, *newSSOToken)

		clio.Successf("Successfully logged into Start URL: %s", ssoStartUrl)

		return nil
	},
}

type AWSSSOSource struct {
	SSORegion string
	StartURL  string
	SSOScopes []string
}

func (s AWSSSOSource) GetProfiles(ctx context.Context) ([]awsconfigfile.SSOProfile, error) {
	region, err := cfaws.ExpandRegion(s.SSORegion)
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRetryer(func() aws.Retryer {
		return retry.NewStandard(func(so *retry.StandardOptions) {
			// We've disabled the built-in AWS client rate limiting below because we're using uber's rate limit package to rate limit the AWS SSO API calls
			// The issue is caused because all Go routines use the same token bucket and it runs out of tokens. Link to the solution: https://github.com/aws/aws-sdk-go-v2/issues/1665
			so.RateLimiter = ratelimit.NewTokenRateLimit(100000)
			so.MaxAttempts = 15
		})
	}))
	if err != nil {
		return nil, err
	}
	cfg.Region = region
	secureSSOTokenStorage := securestorage.NewSecureSSOTokenStorage()
	ssoTokenFromSecureCache := secureSSOTokenStorage.GetValidSSOToken(ctx, s.StartURL)
	ssoTokenFromPlainText := cfaws.GetValidSSOTokenFromPlaintextCache(s.StartURL)

	// depending on whether creds come from secure storage or ~/.aws/sso/cache, we need to use different access tokens
	var accessToken string

	// we also want to store this in the secure cache to prevent subsequent logins
	if ssoTokenFromPlainText != nil {
		secureSSOTokenStorage.StoreSSOToken(s.StartURL, *ssoTokenFromPlainText)
	}

	if ssoTokenFromSecureCache == nil && ssoTokenFromPlainText == nil {
		// otherwise, login with SSO
		ssoTokenFromSecureCache, err = idclogin.Login(ctx, cfg, s.StartURL, s.SSOScopes)
		if err != nil {
			return nil, err
		}
		secureSSOTokenStorage.StoreSSOToken(s.StartURL, *ssoTokenFromSecureCache)
	}

	if ssoTokenFromSecureCache != nil {
		accessToken = ssoTokenFromSecureCache.AccessToken
	} else {
		accessToken = ssoTokenFromPlainText.AccessToken
	}

	clio.Info("listing available profiles from AWS IAM Identity Center...")

	ssoClient := sso.NewFromConfig(cfg)
	g, gctx := errgroup.WithContext(ctx)
	var mu sync.Mutex

	// if the token is nil fetch it from config instead
	var ssoProfiles []awsconfigfile.SSOProfile
	listAccountsNextToken := ""
	bar := progressbar.Default(1)
	isFirstLoop := true
	// Setting the rate limit to 20 since IAM Identity Center APIs have a throttle maximum of 20 transactions per second (TPS) (https://docs.aws.amazon.com/singlesignon/latest/userguide/limits.html)
	rl := uberratelimit.New(20)
	for {
		listAccountsInput := sso.ListAccountsInput{
			AccessToken: &accessToken,
		}
		if listAccountsNextToken != "" {
			listAccountsInput.NextToken = &listAccountsNextToken
		}
		rl.Take()
		listAccountsOutput, err := ssoClient.ListAccounts(ctx, &listAccountsInput)
		if err != nil {
			return nil, err
		}
		//`isFirstLoop` is used to assign the initial max of the progress bar
		if isFirstLoop {
			bar.ChangeMax(len(listAccountsOutput.AccountList) + 1)
			isFirstLoop = false
		} else {
			bar.ChangeMax(bar.GetMax() + len(listAccountsOutput.AccountList))
		}
		for _, accountLoop := range listAccountsOutput.AccountList {
			account := accountLoop
			g.Go(func() error {
				listAccountRolesNextToken := ""
				for {
					listAccountRolesInput := sso.ListAccountRolesInput{
						AccessToken: &accessToken,
						AccountId:   account.AccountId,
					}
					if listAccountRolesNextToken != "" {
						listAccountRolesInput.NextToken = &listAccountRolesNextToken
					}
					rl.Take()
					listAccountRolesOutput, err := ssoClient.ListAccountRoles(gctx, &listAccountRolesInput)
					if err != nil {
						return err
					}
					mu.Lock()
					for _, role := range listAccountRolesOutput.RoleList {
						ssoProfiles = append(ssoProfiles, awsconfigfile.SSOProfile{
							SSOStartURL:   s.StartURL,
							SSORegion:     region,
							AccountID:     *role.AccountId,
							AccountName:   *account.AccountName,
							RoleName:      *role.RoleName,
							GeneratedFrom: "aws-sso",
						})
					}
					mu.Unlock()

					if listAccountRolesOutput.NextToken == nil {
						break
					}

					listAccountRolesNextToken = *listAccountRolesOutput.NextToken
				}
				err = bar.Add(1)
				if err != nil {
					return err
				}
				return nil
			})
		}

		if listAccountsOutput.NextToken == nil {
			break
		}

		listAccountsNextToken = *listAccountsOutput.NextToken
	}
	err = g.Wait()
	if err != nil {
		return nil, err
	}
	bar.ChangeMax(bar.GetMax() - 1)
	err = bar.Finish()
	if err != nil {
		return nil, err
	}
	return ssoProfiles, nil
}

func coalesceString(s1, s2 string) string {
	if s1 != "" {
		return s1
	}
	return s2
}
