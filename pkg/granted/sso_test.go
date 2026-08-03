package granted

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/ini.v1"
)

func TestResolveDefaultRegion(t *testing.T) {
	tests := []struct {
		name        string
		flagValue   string
		configValue string
		want        string
		wantErr     bool
	}{
		{
			name:        "empty returns empty so no region key is written",
			flagValue:   "",
			configValue: "",
			want:        "",
		},
		{
			name:      "fully-qualified flag value passes through",
			flagValue: "eu-west-1",
			want:      "eu-west-1",
		},
		{
			name:      "shorthand flag value is expanded",
			flagValue: "ew1",
			want:      "eu-west-1",
		},
		{
			name:        "config value is used when flag is empty",
			configValue: "us-east-1",
			want:        "us-east-1",
		},
		{
			name:        "flag value takes precedence over config",
			flagValue:   "ap-southeast-2",
			configValue: "us-east-1",
			want:        "ap-southeast-2",
		},
		{
			name:      "invalid shorthand returns an error",
			flagValue: "x",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDefaultRegion(tt.flagValue, tt.configValue)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("resolveDefaultRegion(%q, %q) = %q, want %q", tt.flagValue, tt.configValue, got, tt.want)
			}
		})
	}
}

func TestResolveCredentialProcessBinaryPath(t *testing.T) {
	got, err := resolveCredentialProcessBinaryPath()
	if err != nil {
		t.Fatal(err)
	}

	if got == "" {
		t.Fatal("expected a non-empty binary path")
	}

	if !filepath.IsAbs(got) {
		t.Fatalf("expected an absolute path, got %q", got)
	}

	want, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	if got != want {
		t.Fatalf("resolveCredentialProcessBinaryPath() = %q, want %q", got, want)
	}
}

func TestApplyCredentialProcessBinaryPath(t *testing.T) {
	config, err := ini.Load([]byte(`
[profile generated]
common_fate_generated_from = aws-sso
credential_process = granted credential-process --profile generated

[profile regular]
credential_process = granted credential-process --profile regular

[profile other-generator]
common_fate_generated_from = custom
credential_process = granted credential-process --profile other-generator
`))
	if err != nil {
		t.Fatal(err)
	}

	applyCredentialProcessBinaryPath(config, "/usr/local/bin/granted")

	tests := []struct {
		section string
		want    string
	}{
		{
			section: "profile generated",
			want:    "/usr/local/bin/granted credential-process --profile generated",
		},
		{
			section: "profile regular",
			want:    "granted credential-process --profile regular",
		},
		{
			section: "profile other-generator",
			want:    "granted credential-process --profile other-generator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.section, func(t *testing.T) {
			got := config.Section(tt.section).Key("credential_process").String()
			if got != tt.want {
				t.Fatalf("credential_process = %q, want %q", got, tt.want)
			}
		})
	}
}
