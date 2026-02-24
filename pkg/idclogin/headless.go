package idclogin

import "os"

// IsHeadlessEnvironment returns true if the current environment is likely
// a headless or remote session where a local browser redirect to 127.0.0.1
// would not work (e.g., SSH sessions, containers, CI).
//
// In these environments, the device code flow should be used instead of
// authorization code with PKCE.
func IsHeadlessEnvironment() bool {
	// SSH session indicators
	for _, env := range []string{"SSH_CLIENT", "SSH_TTY", "SSH_CONNECTION"} {
		if os.Getenv(env) != "" {
			return true
		}
	}

	// Container indicators
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// CI environment indicators
	for _, env := range []string{"CI", "CODESPACES", "CLOUD_SHELL"} {
		if os.Getenv(env) != "" {
			return true
		}
	}

	return false
}
