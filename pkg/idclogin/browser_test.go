package idclogin

import (
	"testing"

	"github.com/fwdcloudsec/granted/pkg/browser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLauncherForPath(t *testing.T) {
	const url = "https://example.awsapps.com/start/#/device?user_code=ABCD-EFGH"

	// 'open' on macOS, 'xdg-open' on Linux.
	open := browser.OpenCommand()

	tests := []struct {
		name    string
		path    string
		profile string
		want    []string
	}{
		{
			name: "safari_is_launched_with_open",
			path: "/Applications/Safari.app/Contents/MacOS/Safari",
			want: []string{open, "-a", "Safari", url},
		},
		{
			name: "firefox_keeps_its_own_launcher",
			path: "/usr/bin/firefox",
			want: []string{"/usr/bin/firefox", "--new-tab", url},
		},
		{
			name: "unknown_browser_is_executed_directly",
			path: "/opt/some-browser/bin/browser",
			want: []string{"/opt/some-browser/bin/browser", url},
		},
		{
			name: "chrome_without_sso_browser_profile",
			path: "/usr/bin/google-chrome",
			want: []string{"/usr/bin/google-chrome", "--no-first-run", "--no-default-browser-check", url},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := launcherForPath(tt.path, tt.profile)
			require.NoError(t, err)

			got, err := l.LaunchCommand(url, tt.profile)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
