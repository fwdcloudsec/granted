package launcher

type FirefoxDevEdition struct {
	ExecutablePath string
}

func (l FirefoxDevEdition) LaunchCommand(url string, profile string) ([]string, error) {
	return firefoxLaunchCommand(l.ExecutablePath, url), nil
}

func (l FirefoxDevEdition) UseForkProcess() bool { return macAppBundle(l.ExecutablePath) == "" }
