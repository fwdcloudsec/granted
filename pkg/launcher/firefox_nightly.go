package launcher

type FirefoxNightly struct {
	ExecutablePath string
}

func (l FirefoxNightly) LaunchCommand(url string, profile string) ([]string, error) {
	return firefoxLaunchCommand(l.ExecutablePath, url), nil
}

func (l FirefoxNightly) UseForkProcess() bool { return macAppBundle(l.ExecutablePath) == "" }
