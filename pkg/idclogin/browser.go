package idclogin

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/common-fate/clio"
	"github.com/common-fate/clio/clierr"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/forkprocess"
	"github.com/fwdcloudsec/granted/pkg/launcher"
	"github.com/pkg/browser"
)

// openBrowser opens the given URL in the user's configured browser,
// respecting Granted's custom browser settings. If the browser fails to open,
// it returns an error.
func openBrowser(url string) error {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	// The browser path comes from the user's local Granted configuration file,
	// not from untrusted input.
	config, err := grantedConfig.Load()
	if err != nil {
		return err
	}

	if config.SSOBrowserLaunchTemplate != nil {
		return openWithLaunchTemplate(config, url)
	}

	if config.CustomSSOBrowserPath != "" {
		return openWithCustomPath(config.CustomSSOBrowserPath, url)
	}

	return browser.OpenURL(url)
}

func openWithLaunchTemplate(config *grantedConfig.Config, url string) error {
	l, err := launcher.CustomFromLaunchTemplate(config.SSOBrowserLaunchTemplate, []string{})
	if errors.Is(err, launcher.ErrLaunchTemplateNotConfigured) {
		return errors.New("error configuring custom browser, ensure that [SSOBrowserLaunchTemplate] is specified in your Granted config file")
	}
	if err != nil {
		return err
	}

	args, err := l.LaunchCommand(url, "")
	if err != nil {
		return fmt.Errorf("error building browser launch command: %w", err)
	}

	if l.UseForkProcess() {
		clio.Debugf("running command using forkprocess: %s", args)
		cmd, err := forkprocess.New(args...)
		if err != nil {
			return err
		}
		return cmd.Start()
	}

	clio.Debugf("running command without forkprocess: %s", args)
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

func openWithCustomPath(browserPath, url string) error {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(browserPath, url)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	return nil
}

// OpenBrowserWithFallbackMessage opens the browser and logs a helpful message if it fails.
// For SSOBrowserLaunchTemplate failures, this returns a hard error to match
// the original device code flow behavior. For other browser methods, failures
// are logged silently since the URL is printed for manual access.
func OpenBrowserWithFallbackMessage(url string) error {
	clio.Info("If the browser does not open automatically, please open this link: " + url)
	err := openBrowser(url)
	if err != nil {
		// Check if the error originated from a configured launch template.
		// Launch template failures should be surfaced to the user as they
		// indicate a misconfiguration, matching the pre-existing behavior.
		config, loadErr := grantedConfig.Load()
		if loadErr == nil && config.SSOBrowserLaunchTemplate != nil {
			return clierr.New(fmt.Sprintf("Granted was unable to open a browser session automatically due to the following error: %s", err.Error()),
				clierr.Info("You can open the browser session manually using the following url:"),
				clierr.Info(url),
			)
		}
		// For default browser and custom path, fail silently
		clio.Debug(err.Error())
	}
	return nil
}
