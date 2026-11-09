package awsconfigfile

import (
	"testing"

	"github.com/alessio/shellescape"
	"github.com/stretchr/testify/assert"
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
