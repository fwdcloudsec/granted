package launcher

type Zen struct {
	ExecutablePath string
}

func (l Zen) LaunchCommand(url string, profile string) ([]string, error) {
	return firefoxLaunchCommand(l.ExecutablePath, url), nil
}

func (l Zen) UseForkProcess() bool { return macAppBundle(l.ExecutablePath) == "" }
