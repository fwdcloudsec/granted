package launcher

import "github.com/fwdcloudsec/granted/pkg/browser"

type FirefoxDevEdition struct {
	ExecutablePath string
}

func (l FirefoxDevEdition) LaunchCommand(url string, profile string) ([]string, error) {
	if appBundle := macOSAppBundle(l.ExecutablePath); appBundle != "" {
		return []string{browser.OpenCommand(), "-a", appBundle, url}, nil
	}
	return []string{
		l.ExecutablePath,
		"--new-tab",
		url,
	}, nil
}

func (l FirefoxDevEdition) UseForkProcess() bool { return macOSAppBundle(l.ExecutablePath) == "" }
