package launcher

import "github.com/fwdcloudsec/granted/pkg/browser"

type Firefox struct {
	// ExecutablePath is the path to the Firefox binary on the system.
	ExecutablePath string
}

func (l Firefox) LaunchCommand(url string, profile string) ([]string, error) {
	if appBundle := macOSAppBundle(l.ExecutablePath); appBundle != "" {
		return []string{browser.OpenCommand(), "-a", appBundle, url}, nil
	}
	return []string{
		l.ExecutablePath,
		"--new-tab",
		url,
	}, nil
}

func (l Firefox) UseForkProcess() bool { return macOSAppBundle(l.ExecutablePath) == "" }
