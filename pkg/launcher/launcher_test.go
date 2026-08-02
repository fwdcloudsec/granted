package launcher

import (
	"errors"
	"reflect"
	"testing"

	"github.com/fwdcloudsec/granted/pkg/browser"
)

func TestForBrowser(t *testing.T) {
	const url = "https://commonfate.io"

	tests := []struct {
		name    string
		key     string
		path    string
		profile string
		want    []string
		wantErr error
	}{
		{
			// Safari resolves a bare argument as a file path relative to its
			// sandbox container, so it must never be executed with the URL
			// as an argument. This is the regression that motivated ForBrowser.
			name: "safari_uses_open",
			key:  browser.SafariKey,
			path: "/Applications/Safari.app/Contents/MacOS/Safari",
			want: []string{"open", "-a", "Safari", url},
		},
		{
			name: "arc_uses_open",
			key:  browser.ArcKey,
			path: "/Applications/Arc.app/Contents/MacOS/Arc",
			want: []string{"open", "-a", "Arc", url},
		},
		{
			name: "firefox",
			key:  browser.FirefoxKey,
			path: "/usr/bin/firefox",
			want: []string{"/usr/bin/firefox", "--new-tab", url},
		},
		{
			name: "waterfox_uses_firefox_launcher",
			key:  browser.WaterfoxKey,
			path: "/usr/bin/waterfox",
			want: []string{"/usr/bin/waterfox", "--new-tab", url},
		},
		{
			name: "firefox_dev_edition",
			key:  browser.FirefoxDevEditionKey,
			path: "/usr/bin/firefox-developer",
			want: []string{"/usr/bin/firefox-developer", "--new-tab", url},
		},
		{
			name: "firefox_nightly",
			key:  browser.FirefoxNightlyKey,
			path: "/usr/bin/firefox-nightly",
			want: []string{"/usr/bin/firefox-nightly", "--new-tab", url},
		},
		{
			name: "zen",
			key:  browser.ZenKey,
			path: "/usr/bin/zen-browser",
			want: []string{"/usr/bin/zen-browser", "--new-tab", url},
		},
		{
			// The SSO login flow has no browser profile by default. An empty
			// --profile-directory would change which profile Chrome opens.
			name: "chrome_without_profile_omits_profile_directory",
			key:  browser.ChromeKey,
			path: "/usr/bin/google-chrome",
			want: []string{"/usr/bin/google-chrome", "--no-first-run", "--no-default-browser-check", url},
		},
		{
			name: "vivaldi_without_profile",
			key:  browser.VivaldiKey,
			path: "/usr/bin/vivaldi",
			want: []string{"/usr/bin/vivaldi", "--no-first-run", "--no-default-browser-check", url},
		},
		{
			// CustomKey needs the configured launch template and its arguments,
			// which ForBrowser has no access to, so callers resolve it themselves.
			name:    "custom_is_left_to_the_caller",
			key:     browser.CustomKey,
			path:    "/usr/bin/whatever",
			wantErr: ErrUnsupportedBrowser,
		},
		{
			name:    "stdout_is_unsupported",
			key:     browser.StdoutKey,
			wantErr: ErrUnsupportedBrowser,
		},
		{
			name:    "unknown_key_is_unsupported",
			key:     "NOT_A_BROWSER",
			path:    "/usr/bin/whatever",
			wantErr: ErrUnsupportedBrowser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := ForBrowser(tt.key, tt.path, tt.profile)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ForBrowser() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ForBrowser() unexpected error = %v", err)
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

// Direct is the fallback for browsers Granted does not recognise. It must keep
// passing the URL as a bare argument, because that is the behaviour those
// configurations already have.
func TestDirect_LaunchCommand(t *testing.T) {
	l := Direct{ExecutablePath: "/opt/some-browser/bin/browser"}

	got, err := l.LaunchCommand("https://commonfate.io", "ignored-profile")
	if err != nil {
		t.Fatalf("LaunchCommand() unexpected error = %v", err)
	}

	want := []string{"/opt/some-browser/bin/browser", "https://commonfate.io"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LaunchCommand() = %v, want %v", got, want)
	}

	if l.UseForkProcess() {
		t.Error("Direct.UseForkProcess() = true, want false")
	}
}

// The forkprocess library cannot run 'open', so launchers built on it must not
// ask for it.
func TestForBrowser_OpenLaunchersDoNotForkProcess(t *testing.T) {
	for _, key := range []string{browser.SafariKey, browser.ArcKey} {
		l, err := ForBrowser(key, "", "")
		if err != nil {
			t.Fatalf("ForBrowser(%s) unexpected error = %v", key, err)
		}
		if l.UseForkProcess() {
			t.Errorf("ForBrowser(%s).UseForkProcess() = true, want false", key)
		}
	}
}
