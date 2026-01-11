package browser

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	"github.com/common-fate/granted/pkg/config"
	"github.com/common-fate/granted/pkg/testable"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Checks the config to see if the user has already set up their default browser
func UserHasDefaultBrowser(ctx *cli.Context) (bool, error) {
	// just check the config file for the default browser field
	conf, err := config.Load()
	if err != nil {
		return false, err
	}

	// stdout options don't have a path
	if conf.DefaultBrowser == StdoutKey || conf.DefaultBrowser == FirefoxStdoutKey {
		return true, nil
	}
	// Due to a change in the behaviour of the browser detection, this is here to migrate existing users who have already configured granted
	// The change is that the browser path will be saved in the config along with the browser type for all installations, except the Stdout browser types
	// This can be removed in a future version of granted, when everyone is expected to have migrated
	if conf.DefaultBrowser != "" && conf.CustomBrowserPath == "" {
		conf.CustomBrowserPath, _ = DetectInstallation(conf.DefaultBrowser)
		err := conf.Save()
		if err != nil {
			return false, err
		}
	}
	return conf.DefaultBrowser != "" && conf.CustomBrowserPath != "" || conf.AWSConsoleBrowserLaunchTemplate != nil, nil
}

func HandleManualBrowserSelection() (string, error) {
	// didn't find it, request manual input

	withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
	in := survey.Select{
		Message: "Select one of the browsers from the list",
		Options: []string{"Chrome", "Brave", "Edge", "Vivaldi", "Firefox", "Waterfox", "Chromium", "Safari", "Stdout", "FirefoxStdout", "Firefox Developer Edition", "Firefox Nightly", "Arc", "Custom"},
	}
	var selection string
	clio.NewLine()
	err := testable.AskOne(&in, &selection, withStdio)
	if err != nil {
		return "", err
	}

	return selection, nil
}

// finds out which browser the user has as default
func Find() (string, error) {
	outcome := ""
	ops := runtime.GOOS
	switch ops {
	case "windows":
		b, err := HandleWindowsBrowserSearch()
		if err != nil {
			return "", err
		}
		outcome = b
	case "darwin":
		b, err := HandleOSXBrowserSearch()
		if err != nil {
			return "", err
		}
		outcome = b

	case "linux":
		b, err := HandleLinuxBrowserSearch()
		if err != nil {
			return "", err
		}
		outcome = b

	default:
		fmt.Printf("%s os not supported.\n", ops)
	}

	if outcome == "" {
		clio.Warn("Could not find default browser")
		return HandleManualBrowserSelection()
	}

	return outcome, nil
}

func GetBrowserKey(b string) string {
	if strings.Contains(strings.ToLower(b), "chrome") {
		return ChromeKey
	}

	if strings.ToLower(b) == "firefox developer edition" {
		return FirefoxDevEditionKey
	}

	if strings.ToLower(b) == "firefox nightly" {
		return FirefoxNightlyKey
	}

	if strings.Contains(strings.ToLower(b), "brave") {
		return BraveKey
	}
	if strings.Contains(strings.ToLower(b), "edge") {
		return EdgeKey
	}
	if strings.Contains(strings.ToLower(b), "firefoxstdout") {
		return FirefoxStdoutKey
	}
	if strings.Contains(strings.ToLower(b), "firefox") || strings.Contains(strings.ToLower(b), "mozilla") {
		return FirefoxKey
	}
	if strings.Contains(strings.ToLower(b), "waterfox") {
		return WaterfoxKey
	}
	if strings.Contains(strings.ToLower(b), "chromium") {
		return ChromiumKey
	}
	if strings.Contains(strings.ToLower(b), "vivaldi") {
		return VivaldiKey
	}
	if strings.Contains(strings.ToLower(b), "safari") {
		return SafariKey
	}
	if strings.Contains(strings.ToLower(b), "arc") {
		return ArcKey
	}
	if strings.Contains(strings.ToLower(b), "custom") {
		return CustomKey
	}

	return StdoutKey
}

// DetectInstallation checks if the default filepath exists for the browser executables on the current os
// returns the detected path
func DetectInstallation(browserKey string) (string, bool) {
	var bPath []string
	switch browserKey {
	case ChromeKey:
		bPath, _ = ChromePathDefaults()
	case BraveKey:
		bPath, _ = BravePathDefaults()
	case EdgeKey:
		bPath, _ = EdgePathDefaults()
	case FirefoxKey:
		bPath, _ = FirefoxPathDefaults()
	case WaterfoxKey:
		bPath, _ = WaterfoxPathDefaults()
	case ChromiumKey:
		bPath, _ = ChromiumPathDefaults()
	case VivaldiKey:
		bPath, _ = VivaldiPathDefaults()
	case SafariKey:
		bPath, _ = SafariPathDefaults()
	case ArcKey:
		bPath, _ = ArcPathDefaults()
	case FirefoxDevEditionKey:
		bPath, _ = FirefoxDevPathDefaults()
	case FirefoxNightlyKey:
		bPath, _ = FirefoxNightlyPathDefaults()
	default:
		return "", false
	}
	if len(bPath) == 0 {
		return "", false
	}
	for _, p := range bPath {
		_, err := os.Stat(p)
		if err == nil {
			return p, true
		}
	}
	return "", false
}

func HandleBrowserWizard(ctx *cli.Context) (string, error) {
	withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
	browserName, err := Find()
	if err != nil {
		return "", err
	}
	title := cases.Title(language.AmericanEnglish)
	browserTitle := title.String((strings.ToLower(GetBrowserKey(browserName))))
	clio.Info("Thanks for using Granted!")
	clio.Infof("By default, Granted will open the AWS console with this browser: %s", browserTitle)
	clio.Warn("Granted works best with Firefox but also supports Chrome, Brave, and Edge (https://docs.commonfate.io/granted/introduction#supported-browsers). You can change this setting later by running 'granted browser set'")
	in := survey.Confirm{
		Message: "Use Firefox as default Granted browser?",
		Default: true,
	}
	var confirm bool
	err = testable.AskOne(&in, &confirm, withStdio)
	if err != nil {
		return "", err
	}
	if confirm {
		browserName = FirefoxKey
	}

	return browserName, ConfigureBrowserSelection(browserName, "")
}

// ConfigureBrowserSelection will verify the existance of the browser executable and promot for a path if it cannot be found
func ConfigureBrowserSelection(browserName string, path string) error {
	browserKey := GetBrowserKey(browserName)
	withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
	title := cases.Title(language.AmericanEnglish)
	browserTitle := title.String(strings.ToLower(browserKey))
	// We allow users to configure a custom install path if we cannot detect the installation
	browserPath := path

	//load config
	conf, err := config.Load()
	if err != nil {
		return err
	}
	// detect installation
	if browserKey != FirefoxStdoutKey && browserKey != StdoutKey && browserKey != CustomKey {

		if browserPath != "" {
			_, err := os.Stat(browserPath)
			if err != nil {
				return errors.Wrap(err, "provided path is invalid")
			}
		} else {
			customBrowserPath, detected := DetectInstallation(browserKey)
			if !detected {
				clio.Warnf("Granted could not detect an existing installation of %s at known installation paths for your system", browserTitle)
				clio.Info("If you have already installed this browser, you can specify the path to the executable manually")
				validPath := false
				for !validPath {
					// prompt for custom path
					bpIn := survey.Input{Message: fmt.Sprintf("Please enter the full path to your browser installation for %s:", browserTitle)}
					clio.NewLine()
					err := testable.AskOne(&bpIn, &customBrowserPath, withStdio)
					if err != nil {
						return err
					}
					if _, err := os.Stat(customBrowserPath); err == nil {
						validPath = true
					} else {
						clio.Error("The path you entered is not valid")
					}
				}
			}
			browserPath = customBrowserPath
		}

		if browserKey == FirefoxKey || browserKey == WaterfoxKey || browserKey == FirefoxDevEditionKey || browserKey == FirefoxNightlyKey {
			err := RunFirefoxExtensionPrompts(browserPath, browserName)
			if err != nil {
				return err
			}
		}
	}

	//if browser set to default but config does not include browser launch tempalate. add it.
	if browserKey == CustomKey && conf.AWSConsoleBrowserLaunchTemplate == nil {
		conf.AWSConsoleBrowserLaunchTemplate = &config.BrowserLaunchTemplate{
			Command: "",
		}
	}

	// save the detected browser as the default
	conf.DefaultBrowser = browserKey
	conf.CustomBrowserPath = browserPath
	err = conf.Save()
	if err != nil {
		return err
	}
	clio.Successf("Granted will default to using %s", browserTitle)
	return nil
}

func GrantedIntroduction() {
	clio.Info("To change the web browser that Granted uses run: `granted browser set`")
	clio.NewLine()
	clio.Info("Here's how to use Granted to supercharge your cloud access:")
	clio.Info("`assume`                   - search profiles to assume")
	clio.Info("`assume <PROFILE_NAME>`    - assume a profile")
	clio.Info("`assume -c <PROFILE_NAME>` - open the console for the specified profile")

	os.Exit(0)
}

func SSOBrowser(grantedDefaultBrowser string) error {
	withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
	in := &survey.Confirm{
		Message: "Use a different browser than your default browser for SSO login?",
		Default: false,
		Help:    "For example, if you normally use a password manager in Chrome for your AWS login but Chrome is not your default browser, you would choose to use Chrome for SSO logins. You can change this later by running 'granted browser set-sso'",
	}
	var confirm bool
	err := testable.AskOne(in, &confirm, withStdio)
	if err != nil {
		return err
	}
	// save the detected browser as the default
	conf, err := config.Load()
	if err != nil {
		return err
	}
	if confirm {
		browserPath, err := AskAndGetBrowserPath()
		if err != nil {
			return err
		}
		conf.CustomSSOBrowserPath = browserPath
		err = conf.Save()
		if err != nil {
			return err
		}
		clio.Successf("Granted will use %s for SSO login prompts.", browserPath)
	}
	return nil

}

func RunFirefoxExtensionPrompts(browserPath string, browserName string) error {
	clio.Info("In order to use Granted with Firefox you need to download the Granted Firefox addon: https://addons.mozilla.org/en-GB/firefox/addon/granted")
	clio.Info("This addon has minimal permissions and does not access any web page content")

	label := fmt.Sprintf("Open %s to download the extension?", browserName)

	withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
	in := &survey.Select{
		Message: label,
		Options: []string{"Yes", "Already installed", "No"},
	}
	var out string
	clio.NewLine()
	err := testable.AskOne(in, &out, withStdio)
	if err != nil {
		return err
	}

	if out == "No" {
		return errors.New("cancelled browser setup")
	}
	// Allow the user to bypass this step if they have been testing different browsers
	if out == "Already installed" {
		return nil
	}

	cmd := exec.Command(browserPath,
		"--new-tab",
		"https://addons.mozilla.org/en-GB/firefox/addon/granted/")
	err = cmd.Start()
	if err != nil {
		return err
	}

	// detach from this new process because it continues to run
	err = cmd.Process.Release()
	if err != nil {
		return err
	}
	time.Sleep(time.Second * 2)
	confIn := &survey.Confirm{
		Message: "Type Y to continue once you have installed the extension",
		Default: true,
	}
	var confirm bool
	clio.NewLine()
	err = testable.AskOne(confIn, &confirm, withStdio)
	if err != nil {
		return err
	}

	if !confirm {
		return errors.New("cancelled browser setup")
	}
	return nil
}

func AskAndGetBrowserPath() (string, error) {
	clio.Info("Select your SSO default browser")
	outcome, err := HandleManualBrowserSelection()
	if err != nil {
		return "", err
	}

	browserKey := GetBrowserKey(outcome)
	withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
	title := cases.Title(language.AmericanEnglish)
	browserTitle := title.String(strings.ToLower(browserKey))
	// We allow users to configure a custom install path is we cannot detect the installation
	browserPath := ""
	// detect installation
	if browserKey != FirefoxStdoutKey && browserKey != StdoutKey && browserKey != CustomKey {

		customBrowserPath, detected := DetectInstallation(browserKey)
		if !detected {
			clio.Warnf("Granted could not detect an existing installation of %s at known installation paths for your system", browserTitle)
			clio.Info("If you have already installed this browser, you can specify the path to the executable manually")
			validPath := false
			for !validPath {
				// prompt for custom path
				bpIn := survey.Input{Message: fmt.Sprintf("Please enter the full path to your browser installation for %s:", browserTitle)}
				clio.NewLine()
				err := testable.AskOne(&bpIn, &customBrowserPath, withStdio)
				if err != nil {
					return "", err
				}
				if _, err := os.Stat(customBrowserPath); err == nil {
					validPath = true
				} else {
					clio.Error("The path you entered is not valid")
				}
			}
		}
		browserPath = customBrowserPath

	}

	return browserPath, nil
}
