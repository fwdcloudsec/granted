package launcher

import "github.com/fwdcloudsec/granted/pkg/browser"

type Zen struct {
	ExecutablePath string
}

func (l Zen) LaunchCommand(url string, profile string) ([]string, error) {
	if appBundle := macOSAppBundle(l.ExecutablePath); appBundle != "" {
		return []string{browser.OpenCommand(), "-a", appBundle, url}, nil
	}
	return []string{
		l.ExecutablePath,
		"--new-tab",
		url,
	}, nil
}

func (l Zen) UseForkProcess() bool { return macOSAppBundle(l.ExecutablePath) == "" }
