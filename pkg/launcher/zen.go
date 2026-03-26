package launcher

type Zen struct {
	ExecutablePath string
}

func (l Zen) LaunchCommand(url string, profile string) ([]string, error) {
	return []string{
		l.ExecutablePath,
		"--new-tab",
		url,
	}, nil
}

func (l Zen) UseForkProcess() bool { return true }
