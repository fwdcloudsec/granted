package launcher

// Direct launches a browser by executing it with the URL as its only argument.
// It is the fallback for browsers that Granted has no specific handling for.
//
// Note that this does not work for every browser: Safari resolves a bare
// argument as a file path rather than a URL, which is why it has its own
// launcher.
type Direct struct {
	// ExecutablePath is the path to the browser binary on the system.
	ExecutablePath string
}

func (l Direct) LaunchCommand(url string, profile string) ([]string, error) {
	return []string{l.ExecutablePath, url}, nil
}

func (l Direct) UseForkProcess() bool { return false }
