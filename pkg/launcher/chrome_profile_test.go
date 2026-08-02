package launcher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/fwdcloudsec/granted/pkg/browser"
)

// writeLocalState creates a Chrome 'Local State' file under a temporary home
// directory and points the process at it, so that profile lookup can be tested
// without touching the developer's real browser configuration.
func writeLocalState(t *testing.T, infoCache map[string]any) {
	t.Helper()

	var relative string
	switch runtime.GOOS {
	case "darwin":
		relative = ChromePathMac
	case "linux":
		relative = ChromePathLinux
	case "windows":
		relative = ChromePathWindows
	default:
		t.Skipf("unsupported OS %s", runtime.GOOS)
	}

	home := t.TempDir()
	// os.UserHomeDir reads $HOME everywhere except Windows, where it reads
	// %USERPROFILE%.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	stateFile := filepath.Join(home, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(stateFile), 0700); err != nil {
		t.Fatalf("creating Local State directory: %v", err)
	}

	contents := map[string]any{
		"profile": map[string]any{"info_cache": infoCache},
	}
	data, err := json.Marshal(contents)
	if err != nil {
		t.Fatalf("marshalling Local State: %v", err)
	}
	if err := os.WriteFile(stateFile, data, 0600); err != nil {
		t.Fatalf("writing Local State: %v", err)
	}
}

// A profile whose name matches an existing Chrome profile is launched into that
// profile's directory, which is what isolates one assumed role from another.
func TestChromeProfile_LaunchCommand_ResolvesProfileDirectory(t *testing.T) {
	writeLocalState(t, map[string]any{
		"Default":   map[string]any{"name": "Person 1"},
		"Profile 3": map[string]any{"name": "my-aws-profile"},
	})

	l := ChromeProfile{BrowserType: browser.ChromeKey, ExecutablePath: "/usr/bin/google-chrome"}

	got, err := l.LaunchCommand("https://commonfate.io", "my-aws-profile")
	if err != nil {
		t.Fatalf("LaunchCommand() unexpected error = %v", err)
	}

	want := []string{
		"/usr/bin/google-chrome",
		"--profile-directory=Profile 3",
		"--no-first-run",
		"--no-default-browser-check",
		"https://commonfate.io",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LaunchCommand() = %v, want %v", got, want)
	}
}

// An unknown profile name falls back to being used as the directory name, which
// is how a new profile gets created.
func TestChromeProfile_LaunchCommand_UnknownProfileFallsBack(t *testing.T) {
	writeLocalState(t, map[string]any{
		"Default": map[string]any{"name": "Person 1"},
	})

	l := ChromeProfile{BrowserType: browser.ChromeKey, ExecutablePath: "/usr/bin/google-chrome"}

	got, err := l.LaunchCommand("https://commonfate.io", "never-seen-before")
	if err != nil {
		t.Fatalf("LaunchCommand() unexpected error = %v", err)
	}

	want := []string{
		"/usr/bin/google-chrome",
		"--profile-directory=never-seen-before",
		"--no-first-run",
		"--no-default-browser-check",
		"https://commonfate.io",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LaunchCommand() = %v, want %v", got, want)
	}
}

// Chrome profile names cannot contain slashes, so a role name containing one is
// rewritten before lookup.
func TestChromeProfile_LaunchCommand_ReplacesSlashesInProfileName(t *testing.T) {
	writeLocalState(t, map[string]any{
		"Profile 7": map[string]any{"name": "sso-my-role"},
	})

	l := ChromeProfile{BrowserType: browser.ChromeKey, ExecutablePath: "/usr/bin/google-chrome"}

	got, err := l.LaunchCommand("https://commonfate.io", "sso/my-role")
	if err != nil {
		t.Fatalf("LaunchCommand() unexpected error = %v", err)
	}

	if got[1] != "--profile-directory=Profile 7" {
		t.Errorf("LaunchCommand() profile directory = %q, want %q", got[1], "--profile-directory=Profile 7")
	}
}

// With no profile there is nothing to isolate, so no --profile-directory is
// passed at all. Sending an empty one would change which profile Chrome opens.
// The SSO login flow and 'granted console' both launch this way.
func TestChromeProfile_LaunchCommand_NoProfile(t *testing.T) {
	l := ChromeProfile{BrowserType: browser.ChromeKey, ExecutablePath: "/usr/bin/google-chrome"}

	got, err := l.LaunchCommand("https://commonfate.io", "")
	if err != nil {
		t.Fatalf("LaunchCommand() unexpected error = %v", err)
	}

	want := []string{
		"/usr/bin/google-chrome",
		"--no-first-run",
		"--no-default-browser-check",
		"https://commonfate.io",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LaunchCommand() = %v, want %v", got, want)
	}
}
