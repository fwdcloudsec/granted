package registry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
	// Sandbox HOME: loadAWSConfigFile auto-creates ~/.aws/config when missing,
	// so without this it would touch the real user's home dir on a fresh machine.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("AWS_CONFIG_FILE", "")

	_, path, err := loadAWSConfigFile()
	assert.NoError(t, err)
	// Exact match — a substring check would also pass for unrelated paths
	// like "/foo/.aws/config-backup".
	assert.Equal(t, filepath.Join(tmpHome, ".aws", "config"), path)
}
