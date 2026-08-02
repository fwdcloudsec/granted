package idclogin

import (
	"reflect"
	"testing"
)

// launcherForPath is what turns a configured CustomSSOBrowserPath into a launch
// command. Safari is the case that motivated it: executing the Safari binary
// with a URL argument makes Safari resolve it as a file path relative to its
// sandbox container, so the login page never opens.
func TestLauncherForPath(t *testing.T) {
	const url = "https://example.awsapps.com/start/#/device?user_code=ABCD-EFGH"

	tests := []struct {
		name    string
		path    string
		profile string
		want    []string
	}{
		{
			name: "safari_is_launched_with_open",
			path: "/Applications/Safari.app/Contents/MacOS/Safari",
			want: []string{"open", "-a", "Safari", url},
		},
		{
			name: "firefox_keeps_its_own_launcher",
			path: "/usr/bin/firefox",
			want: []string{"/usr/bin/firefox", "--new-tab", url},
		},
		{
			// Unrecognised binaries keep being executed directly, which is the
			// behaviour those configurations already have.
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
			if err != nil {
				t.Fatalf("launcherForPath() unexpected error = %v", err)
			}

			got, err := l.LaunchCommand(url, tt.profile)
			if err != nil {
				t.Fatalf("LaunchCommand() unexpected error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LaunchCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}
