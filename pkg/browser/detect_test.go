package browser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetBrowserKey(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Display names, as offered by HandleManualBrowserSelection.
		{"display_name", "Chrome", ChromeKey},
		{"display_name_multiword", "Firefox Developer Edition", FirefoxDevEditionKey},
		{"display_name_stdout", "Stdout", StdoutKey},
		{"display_name_custom", "Custom", CustomKey},

		// Vendor identifiers, as returned by Find on each platform.
		{"macos_bundle_id", "com.google.chrome", ChromeKey},
		{"macos_bundle_id_safari", "com.apple.Safari", SafariKey},
		{"linux_desktop_file", "firefox.desktop\n", FirefoxKey},
		{"windows_progid", "ChromeHTML", ChromeKey},
		{"windows_progid_edge", "MSEdgeHTM", EdgeKey},

		// Executable paths, as stored in CustomBrowserPath and
		// CustomSSOBrowserPath.
		{"path_safari", "/Applications/Safari.app/Contents/MacOS/Safari", SafariKey},
		{"path_arc", "/Applications/Arc.app/Contents/MacOS/Arc", ArcKey},
		{"path_chrome_mac", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", ChromeKey},
		{"path_firefox_linux", "/usr/bin/firefox", FirefoxKey},
		{"path_waterfox", "/usr/bin/waterfox", WaterfoxKey},
		{"path_zen_linux", "/usr/bin/zen-browser", ZenKey},
		{"path_edge_windows", `\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, EdgeKey},

		// Browsers installed outside their default location must still be
		// recognised, which is why only the base name is matched.
		{"path_homebrew", "/opt/homebrew/bin/firefox", FirefoxKey},
		{"path_snap", "/snap/bin/chromium", ChromiumKey},

		{"unknown", "/opt/some-browser/bin/browser", StdoutKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, GetBrowserKey(tt.input))
		})
	}
}

// Directory components are chosen by the user and routinely contain strings that
// look like browser names. They must not decide which browser gets launched.
func TestGetBrowserKey_IgnoresDirectoryComponents(t *testing.T) {
	paths := []string{
		"/Users/marcus/bin/browser",   // contains "arc"
		"/Users/zenon/bin/browser",    // contains "zen"
		"/opt/edge-cases/bin/browser", // contains "edge"
		"/opt/research/bin/browser",   // contains "arc"
		"/home/safarista/bin/browser", // contains "safari"
		"/srv/chrome-testing/browser", // contains "chrome"
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			assert.Equal(t, StdoutKey, GetBrowserKey(path), "directory components must not select a browser")
		})
	}
}
