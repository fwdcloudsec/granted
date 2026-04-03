package awsconfigfile

import (
	"os"
	"path/filepath"
)

// DefaultSharedConfigFilename returns the SDK's default file path for
// the shared config file (~/.aws/config).
func DefaultSharedConfigFilename() string {
	return filepath.Join(userHomeDir(), ".aws", "config")
}

func userHomeDir() string {
	homedir, _ := os.UserHomeDir()
	return homedir
}
