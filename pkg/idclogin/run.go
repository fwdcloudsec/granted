package idclogin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/common-fate/clio"
	"github.com/common-fate/clio/clierr"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/forkprocess"
	"github.com/fwdcloudsec/granted/pkg/launcher"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/pkg/browser"
)

// Login contains all the steps to complete a device code flow to retrieve an SSO token
func Login(ctx context.Context, cfg aws.Config, startUrl string, scopes []string) (*securestorage.SSOToken, error) {
	ssooidcClient := ssooidc.NewFromConfig(cfg)

	// If scopes aren't provided, default to the legacy non-refreshable configuration
	// by specifying the "sso-portal:*" scope
	// there is a little more info here on this, although the specific "sso-portal:*" scope was taken from the AWS CLI source code.
	// https://docs.aws.amazon.com/cli/latest/userguide/sso-configure-profile-legacy.html
	if len(scopes) == 0 {
		scopes = []string{"sso-portal:*"}
	}

	client, err := ssooidcClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("Granted CLI"),
		ClientType: aws.String("public"),
		Scopes:     scopes,
	})
	if err != nil {
		return nil, err
	}

	// authorize your device using the client registration response
	deviceAuth, err := ssooidcClient.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     client.ClientId,
		ClientSecret: client.ClientSecret,
		StartUrl:     aws.String(startUrl),
	})
	if err != nil {
		return nil, err
	}

	// store the device code in the keychain, so that the Granted browser extension can read it.
	s := securestorage.NewDeviceCodeSecureStorage()
	err = s.StoreUserCode(securestorage.UserCode{
		Code:   *deviceAuth.UserCode,
		Expiry: time.Now().Add(time.Duration(deviceAuth.ExpiresIn) * time.Second),
	})
	if err != nil {
		clio.Errorf("Error storing user code in keychain: %s", err.Error())
	}

	// trigger OIDC login. open browser to login. close tab once login is done. press enter to continue
	url := aws.ToString(deviceAuth.VerificationUriComplete)
	clio.Info("If the browser does not open automatically, please open this link: " + url)

	// check if sso browser path is set
	config, err := grantedConfig.Load()
	if err != nil {
		return nil, err
	}

	if config.SSOBrowserLaunchTemplate != nil {
		l, err := launcher.CustomFromLaunchTemplate(config.SSOBrowserLaunchTemplate, []string{})
		if err == launcher.ErrLaunchTemplateNotConfigured {
			return nil, errors.New("error configuring custom browser, ensure that [SSOBrowserLaunchTemplate] is specified in your Granted config file")
		}
		if err != nil {
			return nil, err
		}

		// now build the actual command to run - e.g. 'firefox --new-tab <URL>'
		args, err := l.LaunchCommand(url, "")
		if err != nil {
			return nil, fmt.Errorf("error building browser launch command: %w", err)
		}

		var startErr error
		if l.UseForkProcess() {
			clio.Debugf("running command using forkprocess: %s", args)
			cmd, err := forkprocess.New(args...)
			if err != nil {
				return nil, err
			}
			startErr = cmd.Start()
		} else {
			clio.Debugf("running command without forkprocess: %s", args)
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			startErr = cmd.Start()
		}

		if startErr != nil {
			return nil, clierr.New(fmt.Sprintf("Granted was unable to open a browser session automatically due to the following error: %s", startErr.Error()),
				// allow them to try open the url manually
				clierr.Info("You can open the browser session manually using the following url:"),
				clierr.Info(url),
			)
		}

	} else if config.CustomSSOBrowserPath != "" {
		cmd := exec.Command(config.CustomSSOBrowserPath, url)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		err = cmd.Start()
		if err != nil {
			// fail silently
			clio.Debug(err.Error())
		} else {
			// detach from this new process because it continues to run
			err = cmd.Process.Release()
			if err != nil {
				// fail silently
				clio.Debug(err.Error())
			}
		}
	} else {
		err = browser.OpenURL(url)
		if err != nil {
			// fail silently
			clio.Debug(err.Error())
		}
	}

	clio.Info("Awaiting AWS authentication in the browser")
	clio.Info("You will be prompted to authenticate with AWS in the browser, then you will be prompted to 'Allow'")
	clio.Infof("Code: %s", *deviceAuth.UserCode)

	pc := getPollingConfig(deviceAuth)

	token, err := pollToken(ctx, ssooidcClient, *client.ClientSecret, *client.ClientId, *deviceAuth.DeviceCode, pc)
	if err != nil {
		return nil, err
	}

	result := securestorage.SSOToken{
		AccessToken:           *token.AccessToken,
		Expiry:                time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		ClientID:              *client.ClientId,
		ClientSecret:          *client.ClientSecret,
		RegistrationExpiresAt: time.Unix(client.ClientSecretExpiresAt, 0),
		RefreshToken:          token.RefreshToken,
		Region:                cfg.Region,
	}

	return &result, nil
}
