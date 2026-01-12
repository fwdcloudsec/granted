package assume

import (
	"errors"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	cfflags "github.com/fwdcloudsec/granted/pkg/urfav_overrides"
	"github.com/urfave/cli/v2"
)

// SSOProfileFromFlags will prepare a profile to be assumed from cli flags
func SSOProfileFromFlags(c *cli.Context) (*cfaws.Profile, error) {
	err := ValidateSSOFlags(c)
	if err != nil {
		return nil, err
	}
	s := &cfaws.AwsSsoAssumer{}
	ssoStartURL, ssoRegion, accountID, roleName := ssoFlags(c)
	p := &cfaws.Profile{
		Name:        roleName,
		ProfileType: s.Type(),
		AWSConfig: config.SharedConfig{
			SSOAccountID: accountID,
			SSORoleName:  roleName,
			SSORegion:    ssoRegion,
			SSOStartURL:  ssoStartURL,
		},
		Initialised: true,
	}
	return p, nil
}

// SSOProfileFromEnv will prepare a profile to be assumed from environment variables
func SSOProfileFromEnv() (*cfaws.Profile, error) {
	ssoStartURL := os.Getenv("GRANTED_SSO_START_URL")
	ssoRegion := os.Getenv("GRANTED_SSO_REGION")
	accountID := os.Getenv("GRANTED_SSO_ACCOUNT_ID")
	roleName := os.Getenv("GRANTED_SSO_ROLE_NAME")
	if ssoStartURL == "" || ssoRegion == "" || accountID == "" || roleName == "" {
		return nil, errors.New("one of the require environment variables was not found while loading an sso profile ['GRANTED_SSO_START_URL','GRANTED_SSO_REGION','GRANTED_SSO_ACCOUNT_ID','GRANTED_SSO_ROLE_NAME']")
	}
	s := &cfaws.AwsSsoAssumer{}
	p := &cfaws.Profile{
		Name:        roleName,
		ProfileType: s.Type(),
		AWSConfig: config.SharedConfig{
			SSOAccountID: accountID,
			SSORoleName:  roleName,
			SSORegion:    ssoRegion,
			SSOStartURL:  ssoStartURL,
		},
		Initialised: true,
	}
	return p, nil
}

func ssoFlags(c *cli.Context) (ssoStartURL, ssoRegion, accountID, roleName string) {
	assumeFlags, err := cfflags.New("assumeFlags", GlobalFlags(), c)
	if err != nil {
		return
	}
	ssoStartURL = assumeFlags.String("sso-start-url")
	ssoRegion = assumeFlags.String("sso-region")
	accountID = assumeFlags.String("account-id")
	roleName = assumeFlags.String("role-name")
	return
}
func ValidateSSOFlags(c *cli.Context) error {
	ssoStartURL, ssoRegion, accountID, roleName := ssoFlags(c)
	if c.Bool("sso") {
		good := ssoStartURL != "" && ssoRegion != "" && accountID != "" && roleName != ""
		if !good {
			return errors.New("flags [sso-start-url, sso-region, account-id, role-name] are required to use the -sso flag")
		}
	} else if ssoStartURL != "" || ssoRegion != "" || accountID != "" || roleName != "" {
		return errors.New("flags [sso-start-url, sso-region, account-id, role-name] can only be used with the -sso flag")
	}
	return nil
}
