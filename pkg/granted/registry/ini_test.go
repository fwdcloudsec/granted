package registry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDefaultAWSConfigLocation(t *testing.T) {
	tests := []struct {
		name       string
		envValue   string
		wantCustom bool
	}{
		{
			name:       "uses AWS_CONFIG_FILE when set",
			envValue:   "/custom/path/config",
			wantCustom: true,
		},
		{
			name:       "falls back to default when not set",
			envValue:   "",
			wantCustom: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AWS_CONFIG_FILE", tt.envValue)

			got, err := getDefaultAWSConfigLocation()
			assert.NoError(t, err)
			if tt.wantCustom {
				assert.Equal(t, tt.envValue, got)
			} else {
				assert.Contains(t, got, ".aws/config")
			}
		})
	}
}

func TestLoadAWSConfigFile_RespectsEnvVar(t *testing.T) {
	// Create a temp dir with an AWS config file
	tmpDir := t.TempDir()
	customConfigPath := filepath.Join(tmpDir, "custom-aws-config")
	err := os.WriteFile(customConfigPath, []byte("[profile test]\nregion = us-east-1\n"), 0600)
	assert.NoError(t, err)

	t.Setenv("AWS_CONFIG_FILE", customConfigPath)

	cfg, path, err := loadAWSConfigFile()
	assert.NoError(t, err)
	assert.Equal(t, customConfigPath, path)
	assert.NotNil(t, cfg)

	// Verify it loaded the correct file
	sec, err := cfg.GetSection("profile test")
	assert.NoError(t, err)
	assert.Equal(t, "us-east-1", sec.Key("region").String())
}

func TestLoadAWSConfigFile_DefaultPath(t *testing.T) {
	t.Setenv("AWS_CONFIG_FILE", "")

	_, path, err := loadAWSConfigFile()
	assert.NoError(t, err)
	assert.Contains(t, path, ".aws/config")
}
