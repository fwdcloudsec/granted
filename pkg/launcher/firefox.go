package launcher

import (
	"runtime"
	"strings"

	"github.com/fwdcloudsec/granted/pkg/browser"
)

// goos is runtime.GOOS, overridable in tests.
var goos = runtime.GOOS

type Firefox struct {
	// ExecutablePath is the path to the Firefox binary on the system.
	ExecutablePath string
}

func (l Firefox) LaunchCommand(url string, profile string) ([]string, error) {
	return firefoxLaunchCommand(l.ExecutablePath, url), nil
}

func (l Firefox) UseForkProcess() bool { return macAppBundle(l.ExecutablePath) == "" }

// firefoxLaunchCommand builds the launch command shared by the Firefox-based
// browsers.
//
// On macOS, a browser installed as an app bundle is launched through 'open'
// so that it runs under its own privacy (TCC) identity. Since macOS 27,
// ~/Library/Application Support/Firefox is a protected location. A Firefox
// process forked directly by Granted inherits the terminal's identity, cannot
// read profiles.ini, and fails with "Your Firefox profile cannot be loaded.
// It may be missing or inaccessible." Launched through 'open', Firefox opens
// the URL in a new tab of the running instance, as --new-tab does.
func firefoxLaunchCommand(executablePath, url string) []string {
	if app := macAppBundle(executablePath); app != "" {
		// -u makes 'open' treat the argument as a URL even though the
		// ext+granted-containers: scheme is not registered with the system.
		return []string{browser.OpenCommand(), "-a", app, "-u", url}
	}
	return []string{executablePath, "--new-tab", url}
}

// macAppBundle returns the .app bundle that contains executablePath, for
// example /Applications/Firefox.app for
// /Applications/Firefox.app/Contents/MacOS/firefox. It returns "" when not on
// macOS or when the executable is not inside an app bundle.
func macAppBundle(executablePath string) string {
	if goos != "darwin" {
		return ""
	}
	const marker = ".app/Contents/MacOS/"
	i := strings.Index(executablePath, marker)
	if i < 0 {
		return ""
	}
	return executablePath[:i+len(".app")]
}
