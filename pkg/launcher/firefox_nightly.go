package launcher

import "github.com/fwdcloudsec/granted/pkg/browser"

type FirefoxNightly struct {
	ExecutablePath string
}

func (l FirefoxNightly) LaunchCommand(url string, profile string) ([]string, error) {
	if appBundle := macOSAppBundle(l.ExecutablePath); appBundle != "" {
		return []string{browser.OpenCommand(), "-a", appBundle, url}, nil
	}
	return []string{
		l.ExecutablePath,
		"--new-tab",
		url,
	}, nil
}

func (l FirefoxNightly) UseForkProcess() bool { return macOSAppBundle(l.ExecutablePath) == "" }
