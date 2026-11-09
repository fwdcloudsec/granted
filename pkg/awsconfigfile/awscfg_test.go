package awsconfigfile

import (
	"testing"

	"github.com/alessio/shellescape"
	"github.com/stretchr/testify/assert"
	"gopkg.in/ini.v1"
)

func TestSSOProfile_ToIni_QuotesCredentialProcessArgs(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		providerURL string
	}{
		{
			name:        "simple profile",
			profileName: "my-account/my-role",
		},
		{
			name:        "profile name with injected flag",
			profileName: "foo --url http://evil.example.com",
		},
		{
			name:        "provider url with shell metacharacters",
			profileName: "my-account/my-role",
			providerURL: "http://example.com/$(rm -rf ~)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := SSOProfile{ProviderURL: tt.providerURL}

			entry := p.ToIni(tt.profileName, false)
			cp, ok := entry.(*credentialProcessProfile)
			if !assert.True(t, ok) {
				return
			}

			assert.Contains(t, cp.CredProcess, shellescape.Quote(tt.profileName))
			if tt.providerURL != "" {
				assert.Contains(t, cp.CredProcess, shellescape.Quote(tt.providerURL))
			}

			// the raw, unquoted values must never appear verbatim once they
			// contain shell metacharacters, since credential_process is
			// parsed with shell-word splitting.
			if tt.profileName != shellescape.Quote(tt.profileName) {
				assert.NotContains(t, cp.CredProcess, " "+tt.profileName+" ")
			}
		})
	}
}

func TestSSOProfile_ToIni_NoCredentialProcess(t *testing.T) {
	p := SSOProfile{SSOStartURL: "https://start.example.com", SSORegion: "us-east-1", AccountID: "111111111111", RoleName: "Admin"}

	entry := p.ToIni("my-account/Admin", true)
	rp, ok := entry.(*regularProfile)
	if !assert.True(t, ok) {
		return
	}
	assert.Equal(t, "https://start.example.com", rp.SSOStartURL)
	assert.Equal(t, "us-east-1", rp.SSORegion)
	assert.Equal(t, "111111111111", rp.SSOAccountID)
	assert.Equal(t, "Admin", rp.SSORoleName)
}

func TestNormalizeAccountName(t *testing.T) {
	assert.Equal(t, "my-company", normalizeAccountName("my company"))
	assert.Equal(t, "no-change", normalizeAccountName("no-change"))
}

func TestMerge_AddsNewProfiles(t *testing.T) {
	cfg := ini.Empty()
	err := Merge(MergeOpts{
		Config: cfg,
		Profiles: []SSOProfile{
			{SSOStartURL: "https://start.example.com", AccountName: "my account", RoleName: "Admin"},
		},
		NoCredentialProcess: true,
	})
	assert.NoError(t, err)

	assert.True(t, cfg.HasSection("profile my-account/Admin"))
	sec := cfg.Section("profile my-account/Admin")
	assert.Equal(t, "https://start.example.com", sec.Key("sso_start_url").Value())
}

func TestMerge_UsesCustomSectionNameTemplate(t *testing.T) {
	cfg := ini.Empty()
	err := Merge(MergeOpts{
		Config:              cfg,
		SectionNameTemplate: "{{ .AccountID }}-{{ .RoleName }}",
		Profiles: []SSOProfile{
			{AccountID: "111111111111", RoleName: "Admin"},
		},
		NoCredentialProcess: true,
	})
	assert.NoError(t, err)
	assert.True(t, cfg.HasSection("profile 111111111111-Admin"))
}

func TestMerge_AppliesPrefix(t *testing.T) {
	cfg := ini.Empty()
	err := Merge(MergeOpts{
		Config: cfg,
		Prefix: "work-",
		Profiles: []SSOProfile{
			{AccountName: "account", RoleName: "Admin"},
		},
		NoCredentialProcess: true,
	})
	assert.NoError(t, err)
	assert.True(t, cfg.HasSection("profile work-account/Admin"))
}

func TestMerge_PrunesProfilesForMatchingStartURLsNotInProfiles(t *testing.T) {
	cfg := ini.Empty()

	// an existing, previously generated profile for a start URL we're about to prune
	sec, err := cfg.NewSection("profile old-account/OldRole")
	assert.NoError(t, err)
	_, err = sec.NewKey("granted_sso_start_url", "https://start.example.com")
	assert.NoError(t, err)
	_, err = sec.NewKey("granted_generated_from", "aws-sso")
	assert.NoError(t, err)

	// a manually-written profile with the same start URL but no generated_from marker:
	// must survive pruning since Granted didn't create it.
	manualSec, err := cfg.NewSection("profile manual-account/ManualRole")
	assert.NoError(t, err)
	_, err = manualSec.NewKey("sso_start_url", "https://start.example.com")
	assert.NoError(t, err)

	err = Merge(MergeOpts{
		Config:              cfg,
		Profiles:            []SSOProfile{}, // no profiles found this time for this start URL
		PruneStartURLs:      []string{"https://start.example.com"},
		NoCredentialProcess: true,
	})
	assert.NoError(t, err)

	assert.False(t, cfg.HasSection("profile old-account/OldRole"))
	assert.True(t, cfg.HasSection("profile manual-account/ManualRole"))
}

func TestMerge_LegacyCommonFateGeneratedFromKeyIsAlsoPruned(t *testing.T) {
	cfg := ini.Empty()
	sec, err := cfg.NewSection("profile legacy-account/Role")
	assert.NoError(t, err)
	_, err = sec.NewKey("sso_start_url", "https://start.example.com")
	assert.NoError(t, err)
	_, err = sec.NewKey("common_fate_generated_from", "aws-sso")
	assert.NoError(t, err)

	err = Merge(MergeOpts{
		Config:              cfg,
		Profiles:            []SSOProfile{},
		PruneStartURLs:      []string{"https://start.example.com"},
		NoCredentialProcess: true,
	})
	assert.NoError(t, err)
	assert.False(t, cfg.HasSection("profile legacy-account/Role"))
}

func TestMerge_ReplacesExistingSectionOfSameName(t *testing.T) {
	cfg := ini.Empty()
	sec, err := cfg.NewSection("profile my-account/Admin")
	assert.NoError(t, err)
	_, err = sec.NewKey("region", "eu-west-1")
	assert.NoError(t, err)

	err = Merge(MergeOpts{
		Config: cfg,
		Profiles: []SSOProfile{
			{AccountName: "my-account", RoleName: "Admin", Region: "us-east-1"},
		},
		NoCredentialProcess: true,
	})
	assert.NoError(t, err)

	sec = cfg.Section("profile my-account/Admin")
	assert.Equal(t, "us-east-1", sec.Key("region").Value())
}
