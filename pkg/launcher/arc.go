package launcher

import "github.com/fwdcloudsec/granted/pkg/browser"

type Arc struct {
}

func (l Arc) LaunchCommand(url string, profile string) ([]string, error) {
	cmd := browser.OpenCommand()
	return []string{cmd, "-a", "Arc", url}, nil
}

func (l Arc) UseForkProcess() bool { return false }
