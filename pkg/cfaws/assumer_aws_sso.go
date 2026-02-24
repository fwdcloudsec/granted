package cfaws

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/idclogin"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/hako/durafmt"
	"github.com/pkg/errors"
	"gopkg.in/ini.v1"
)

// Implements Assumer
type AwsSsoAssumer struct {
}

func (asa *AwsSsoAssumer) AssumeTerminal(ctx context.Context, c *Profile, configOpts ConfigOpts) (aws.Credentials, error) {
	return c.SSOLogin(ctx, configOpts)
}

func (asa *AwsSsoAssumer) AssumeConsole(ctx context.Context, c *Profile, configOpts ConfigOpts) (aws.Credentials, error) {
	return c.SSOLogin(ctx, configOpts)
}

func (asa *AwsSsoAssumer) Type() string {
	return "AWS_SSO"
}

// Matches the profile type on whether it is an sso profile by checking for ssoaccountid.
func (asa *AwsSsoAssumer) ProfileMatchesType(rawProfile *ini.Section, parsedProfile config.SharedConfig) bool {
	return parsedProfile.SSOAccountID != ""
}

func (c *Profile) SSOLoginWithToken(ctx context.Context, cfg *aws.Config, accessToken *string, secureSSOTokenStorage securestorage.SSOTokensSecureStorage, configOpts ConfigOpts) (aws.Credentials, error) {
	rootProfile := c
	requiresAssuming := false
	if len(c.Parents) > 0 {
		rootProfile = c.Parents[0]

		requiresAssuming = true
	}

	ssoTokenKey := rootProfile.SSOStartURL()
	cfg.Region = rootProfile.SSORegion()
	// create sso client
	ssoClient := sso.NewFromConfig(*cfg)
	var res *ssotypes.RoleCredentials

	if configOpts.ShouldRetryAssuming != nil && *configOpts.ShouldRetryAssuming {
		roleCredentials, err := c.getRoleCredentialsWithRetry(ctx, ssoClient, accessToken, rootProfile)
		if err != nil {
			var unauthorised *ssotypes.UnauthorizedException
			if errors.As(err, &unauthorised) {
				// possible error with the access token we used, in this case we should clear our cached token and request a new one if the user tries again
				secureSSOTokenStorage.ClearSSOToken(ssoTokenKey)
			}
			return aws.Credentials{}, err
		}
		res = roleCredentials
	} else {
		role, err := ssoClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{AccessToken: accessToken, AccountId: &rootProfile.AWSConfig.SSOAccountID, RoleName: &rootProfile.AWSConfig.SSORoleName})
		if err != nil {
			serr, ok := err.(*smithy.OperationError)
			if ok {
				// If the err is of type ForbiddenRequest the user doesn't have an
				// IAM Identity Center account assignment which matches the one requested.
				if httpErr, ok := serr.Err.(*awshttp.ResponseError); ok {
					if httpErr.HTTPStatusCode() == http.StatusForbidden {
						return aws.Credentials{}, NoAccessError{Err: err}
					}
				}

			}

			var unauthorised *ssotypes.UnauthorizedException
			if errors.As(err, &unauthorised) {
				// possible error with the access token we used, in this case we should clear our cached token and request a new one if the user tries again
				secureSSOTokenStorage.ClearSSOToken(ssoTokenKey)
			}
			return aws.Credentials{}, err
		}

		res = role.RoleCredentials
	}

	rootCreds := TypeRoleCredsToAwsCreds(*res)
	credProvider := &CredProv{rootCreds}

	if requiresAssuming {
		// return creds, nil
		toAssume := append([]*Profile{}, c.Parents[1:]...)
		toAssume = append(toAssume, c)
		for i, p := range toAssume {
			region, err := c.Region(ctx)
			if err != nil {
				return aws.Credentials{}, err
			}
			// in order to support profiles which do not specify a region, we use the default region when assuming the role
			stsClient := sts.New(sts.Options{Credentials: aws.NewCredentialsCache(credProvider), Region: region})
			stsp := stscreds.NewAssumeRoleProvider(stsClient, p.AWSConfig.RoleARN, func(aro *stscreds.AssumeRoleOptions) {
				// all configuration goes in here for this profile
				aro.RoleSessionName = getRoleSessionNameFromProfile(p)
				if p.AWSConfig.MFASerial != "" {
					aro.SerialNumber = &p.AWSConfig.MFASerial
					aro.TokenProvider = MfaTokenProvider
				} else if c.AWSConfig.MFASerial != "" {
					aro.SerialNumber = &c.AWSConfig.MFASerial
					aro.TokenProvider = MfaTokenProvider
				}
				aro.Duration = configOpts.Duration
				if p.AWSConfig.ExternalID != "" {
					aro.ExternalID = &p.AWSConfig.ExternalID
				}
			})
			stsCreds, err := stsp.Retrieve(ctx)
			if err != nil {
				return aws.Credentials{}, err
			}
			// only print for sub assumes because the final credentials are printed at the end of the assume command
			// this is here for visibility into role traversals when assuming a final profile with sso
			if i < len(toAssume)-1 {
				durationDescription := durafmt.Parse(time.Until(stsCreds.Expires) * time.Second).LimitFirstN(1).String()
				clio.Successf("Assumed parent profile: [%s](%s) session credentials will expire %s", p.Name, region, durationDescription)
			}
			credProvider = &CredProv{stsCreds}

		}
	}
	return credProvider.Credentials, nil
}

func (c *Profile) SSOLogin(ctx context.Context, configOpts ConfigOpts) (aws.Credentials, error) {
	rootProfile := c
	if len(c.Parents) > 0 {
		rootProfile = c.Parents[0]
	}
	ssoTokenKey := rootProfile.SSOStartURL() + c.AWSConfig.SSOSessionName
	// if the profile has an sso user configured then suffix the sso token storage key to ensure unique logins
	secureSSOTokenStorage := securestorage.NewSecureSSOTokenStorage()

	var cachedToken *securestorage.SSOToken
	var plainTextToken *securestorage.SSOToken
	if !configOpts.DisableCache {
		cachedToken = secureSSOTokenStorage.GetValidSSOToken(ctx, ssoTokenKey)
		// check if profile has a valid plaintext sso access token
		plainTextToken = GetValidSSOTokenFromPlaintextCache(rootProfile.SSOStartURL())
		// store token to storage to avoid multiple logins
		if plainTextToken != nil {
			secureSSOTokenStorage.StoreSSOToken(ssoTokenKey, *plainTextToken)
		}
	}

	var accessToken *string

	skipAutoLogin := configOpts.UsingCredentialProcess && !configOpts.CredentialProcessAutoLogin
	if skipAutoLogin && cachedToken == nil {
		cmd := "granted sso login"
		startURL := c.SSOStartURL()
		if startURL != "" {
			cmd += " --sso-start-url " + startURL
		}

		region := c.SSORegion()
		if region != "" {
			cmd += " --sso-region " + region
		}

		scopes := c.SSOScopes()
		if len(scopes) > 0 {
			cmd += " --sso-scope " + strings.Join(scopes, ",")
		}

		// if the token exists but is invalid, attempt to clear it so that next login works.
		secureSSOTokenStorage.ClearSSOToken(ssoTokenKey)

		return aws.Credentials{}, fmt.Errorf("error when retrieving credentials from custom process. please login using '%s'", cmd)
	}

	if cachedToken == nil && plainTextToken == nil {
		newCfg := aws.NewConfig()
		newCfg.Region = rootProfile.SSORegion()

		var newSSOToken *securestorage.SSOToken
		var err error

		// Use authorization code flow with PKCE when an sso_session is configured,
		// unless the user has explicitly requested device code flow or we're
		// in a headless environment where the localhost redirect won't work.
		useDeviceCode := configOpts.UseDeviceCode || idclogin.IsHeadlessEnvironment()
		if c.AWSConfig.SSOSessionName != "" && !useDeviceCode {
			newSSOToken, err = idclogin.LoginWithAuthorizationCode(ctx, *newCfg, rootProfile.SSOStartURL(), rootProfile.SSOScopes())
		} else {
			newSSOToken, err = idclogin.Login(ctx, *newCfg, rootProfile.SSOStartURL(), rootProfile.SSOScopes())
		}
		if err != nil {
			return aws.Credentials{}, err
		}

		if !configOpts.DisableCache {
			secureSSOTokenStorage.StoreSSOToken(ssoTokenKey, *newSSOToken)
		}

		cachedToken = newSSOToken
	}

	if cachedToken != nil {
		accessToken = &cachedToken.AccessToken
	} else {
		accessToken = &plainTextToken.AccessToken
	}

	cfg := aws.NewConfig()
	cfg.Region = c.SSORegion()

	return c.SSOLoginWithToken(ctx, cfg, accessToken, secureSSOTokenStorage, configOpts)
}

func (c *Profile) getRoleCredentialsWithRetry(ctx context.Context, ssoClient *sso.Client, accessToken *string, rootProfile *Profile) (*ssotypes.RoleCredentials, error) {
	maxRetry := 5
	var er error
	for i := 0; i < maxRetry; i++ {
		res, err := ssoClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{AccessToken: accessToken, AccountId: &rootProfile.AWSConfig.SSOAccountID, RoleName: &rootProfile.AWSConfig.SSORoleName})
		if err == nil {
			return res.RoleCredentials, nil
		} else {
			serr, ok := err.(*smithy.OperationError)
			if ok {
				// If the err is of type ForbiddenRequest then retry
				if httpErr, ok := serr.Err.(*awshttp.ResponseError); ok {
					if httpErr.HTTPStatusCode() == http.StatusForbidden {
						clio.Debugf("failed assuming attempt %d", i)
						// Increase the backoff duration by a second each time we retry
						time.Sleep(time.Second * time.Duration(i+1))
					}
				}
			} else {
				return nil, err
			}

			er = err
		}
	}

	return nil, errors.Wrap(er, "max retries exceeded")
}
