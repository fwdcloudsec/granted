package chromemsg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/fwdcloudsec/granted/internal/build"
)

type HostManifest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Path           string   `json:"path"`
	Type           string   `json:"type"`
	AllowedOrigins []string `json:"allowed_origins"`
}

func writeManifest(manifestPath string) error {
	executablePath, err := os.Executable()
	if err != nil {
		return err
	}

	executablePath, err = filepath.EvalSymlinks(executablePath)
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		// on windows, the file needs to be 'granted.exe' rather than 'assumego.exe'.
		parent := filepath.Dir(executablePath)
		executablePath = filepath.Join(parent, build.GrantedBinaryName()+".exe")
	}

	manifest := HostManifest{
		Name:        "io.commonfate.granted",
		Description: "Granted BrowserSupport",
		Path:        executablePath,
		Type:        "stdio",
		AllowedOrigins: []string{
			fmt.Sprintf("chrome-extension://%s/", build.ChromeExtensionID),
		},
	}

	file, err := os.Create(manifestPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	return encoder.Encode(manifest)
}
