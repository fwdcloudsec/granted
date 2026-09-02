package cfaws

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	grantedconfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/stretchr/testify/assert"
	"gopkg.in/ini.v1"
)

func TestExportCredsToProfileWithOptions_AppliesSuffix(t *testing.T) {
	tests := []struct {
		name              string
		sourceProfileName string
		applySuffix       bool
		expectedSection   string
		unexpectedSection string
	}{
		{
			name:              "applies configured suffix",
			sourceProfileName: "source-profile",
			applySuffix:       true,
			expectedSection:   "source-profile-team",
			unexpectedSection: "source-profile",
		},
		{
			name:              "skips suffix with custom export name",
			sourceProfileName: "renamed-profile",
			applySuffix:       false,
			expectedSection:   "renamed-profile",
			unexpectedSection: "renamed-profile-team",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpHome := t.TempDir()
			tmpCredsPath := filepath.Join(tmpHome, "aws-credentials")
			t.Setenv("HOME", tmpHome)
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", tmpCredsPath)

			suffix := "team"
			writeGrantedConfigForTest(t, &suffix)

			err := ExportCredsToProfileWithOptions(tt.sourceProfileName, testCreds(), tt.applySuffix)
			assert.NoError(t, err)

			credentialsFile, err := ini.Load(tmpCredsPath)
			assert.NoError(t, err)

			section, err := credentialsFile.GetSection(tt.expectedSection)
			assert.NoError(t, err)
			assert.Equal(t, "AKIA_TEST", section.Key("aws_access_key_id").String())
			assert.Equal(t, "secret_test", section.Key("aws_secret_access_key").String())
			assert.Equal(t, "token_test", section.Key("aws_session_token").String())

			_, err = credentialsFile.GetSection(tt.unexpectedSection)
			assert.Error(t, err)
		})
	}
}

func writeGrantedConfigForTest(t *testing.T, suffix *string) {
	t.Helper()

	grantedFolder := filepath.Join(os.Getenv("HOME"), ".dgranted")
	err := os.MkdirAll(grantedFolder, 0700)
	assert.NoError(t, err)

	cfg := grantedconfig.NewDefaultConfig()
	cfg.ExportCredentialSuffix = suffix
	err = cfg.Save()
	assert.NoError(t, err)
}

func testCreds() aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     "AKIA_TEST",
		SecretAccessKey: "secret_test",
		SessionToken:    "token_test",
	}
}
