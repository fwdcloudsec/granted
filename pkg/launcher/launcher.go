package launcher

import (
	"errors"

	"github.com/fwdcloudsec/granted/pkg/browser"
)

// Launchers give a command that we need to run in order to launch a browser, such as
// 'open <URL>' or 'firefox --new-tab <URL>'. The returned command is a string slice,
// with each element being an argument. (e.g. []string{"firefox", "--new-tab", "<URL>"})
type Launcher interface {
	LaunchCommand(url string, profile string) ([]string, error)
	// UseForkProcess returns true if the launcher implementation should call
	// the forkprocess library.
	//
	// For launchers that use 'open' commands, this should be false,
	// as the forkprocess library causes the following error to appear:
	// 	fork/exec open: no such file or directory
	UseForkProcess() bool
}

// ErrUnsupportedBrowser is returned by ForBrowser for keys it does not handle,
// including CustomKey. Callers decide the fallback: the console commands use
// 'open', and the SSO login flow executes the configured path directly.
var ErrUnsupportedBrowser = errors.New("unsupported browser")

// ForBrowser returns the Launcher to use for a browser key. path is the browser
// executable and profile is the browser profile to isolate the session into.
//
// CustomKey is deliberately not handled here, because both console call sites
// resolve it through CustomFromLaunchTemplate, which needs the configured
// launch template and its arguments.
func ForBrowser(key, path, profile string) (Launcher, error) {
	switch key {
	case browser.ChromeKey, browser.BraveKey, browser.EdgeKey, browser.ChromiumKey, browser.VivaldiKey:
		// ChromeProfile handles an empty profile by launching without one. The SSO
		// login flow has no profile unless --sso-browser-profile was given.
		return ChromeProfile{BrowserType: key, ExecutablePath: path}, nil
	case browser.FirefoxKey, browser.WaterfoxKey:
		return Firefox{ExecutablePath: path}, nil
	case browser.FirefoxDevEditionKey:
		return FirefoxDevEdition{ExecutablePath: path}, nil
	case browser.FirefoxNightlyKey:
		return FirefoxNightly{ExecutablePath: path}, nil
	case browser.ZenKey:
		return Zen{ExecutablePath: path}, nil
	case browser.SafariKey:
		return Safari{}, nil
	case browser.ArcKey:
		return Arc{}, nil
	default:
		return nil, ErrUnsupportedBrowser
	}
}
