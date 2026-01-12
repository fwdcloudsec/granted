package launcher

import "github.com/fwdcloudsec/granted/pkg/browser"

// Open calls the 'open' command to open a URL.
// This is the same command as when you run 'open https://commonfate.io'
// in your own terminal.
type Open struct{}

func (l Open) LaunchCommand(url string, profile string) ([]string, error) {
	cmd := browser.OpenCommand()
	return []string{cmd, url}, nil
}

func (l Open) UseForkProcess() bool { return false }
