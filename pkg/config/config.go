// package config stores configuration around
// user onboarding to granted used to display friendly
// CLI hints and save progress in multi-step workflows,
// such as deploying Granted services to a user's cloud
// environment.
package config

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/BurntSushi/toml"

	"github.com/fwdcloudsec/granted/internal/build"
)

type BrowserLaunchTemplate struct {
	// UseForkProcess specifies whether to use forkprocess to launch the browser.
	//
	// If the launch template command uses 'open', this should be false,
	// as the forkprocess library causes the following error to appear:
	// 	fork/exec open: no such file or directory
	UseForkProcess bool `toml:",omitempty"`

	// Template to use for launching a browser.
	//
	// For example: '/usr/bin/firefox --new-tab --profile={{.Profile}} --url={{.URL}}'
	Command string
}

type Config struct {
	DefaultBrowser string
	// used to override the builtin filepaths for custom installation locations
	CustomBrowserPath       string
	CustomSSOBrowserPath    string
	CustomBrowserExtraFlags []string

	// AWSConsoleBrowserLaunchTemplate is an optional launch template to use
	// for opening the AWS console. If specified it overrides the DefaultBrowser
	// and CustomBrowserPath fields.
	AWSConsoleBrowserLaunchTemplate *BrowserLaunchTemplate `toml:",omitempty"`

	// SSOBrowserLaunchTemplate is an optional launch template to use
	// for opening the SSO auth flow. If specified it overrides the DefaultBrowser
	// and CustomSSOBrowserPath fields.
	SSOBrowserLaunchTemplate *BrowserLaunchTemplate `toml:",omitempty"`

	Keyring                *KeyringConfig `toml:",omitempty"`
	Ordering               string
	ExportCredentialSuffix *string
	// AccessRequestURL is a Granted Approvals URL that users can visit
	// to request access, in the event that we receive a ForbiddenException
	// denying access to assume a particular role.
	//Set this to true to set `--export` to ~/.aws/credentials as default
	ExportCredsToAWS bool `toml:",omitempty"`
	// Set to true to export sso tokens to ~/.aws/sso/cache
	ExportSSOToken bool `toml:",omitempty"`

	AccessRequestURL string `toml:",omitempty"`

	CommonFateDefaultSSOStartURL string `toml:",omitempty"`
	CommonFateDefaultSSORegion   string `toml:",omitempty"`

	// Set this to true to disable usage tips like `To assume this profile again later without needing to select it, run this command:`
	DisableUsageTips bool `toml:",omitempty"`
	// Set this to true to disable credential caching feature when using credential process
	DisableCredentialProcessCache bool `toml:",omitempty"`

	// Set this to true to set `--export-all-env-vars` as default
	DefaultExportAllEnvVar bool `toml:",omitempty"`

	// deprecated in favor of ProfileRegistry
	ProfileRegistryURLS []string `toml:",omitempty"`
	ProfileRegistry     struct {
		// add any global configuration to profile registry here.
		PrefixAllProfiles       bool
		PrefixDuplicateProfiles bool
		SessionName             string            `toml:",omitempty"`
		RequiredKeys            map[string]string `toml:",omitempty"`
		Variables               map[string]string `toml:",omitempty"`
		Registries              []Registry        `toml:",omitempty"`
	} `toml:",omitempty"`

	// CredentialProcessAutoLogin, if 'true', will automatically attempt to
	// authenticate to IAM Identity Center if your AWS SSO
	// access token is expired.
	//
	// Do not set this to 'true' on headless systems, as it
	// will cause Granted to hang during the login process.
	CredentialProcessAutoLogin bool `toml:",omitempty"`

	SSO map[string]AWSSSOConfiguration `toml:",omitempty"`
}

type KeyringConfig struct {
	Backend                 *string `toml:",omitempty"`
	KeychainName            *string `toml:",omitempty"`
	FileDir                 *string `toml:",omitempty"`
	LibSecretCollectionName *string `toml:",omitempty"`
	PassDir                 *string `toml:",omitempty"` // PassDir is the pass password-store directory, ~/ is resolved to the users' home dir
}

type Registry struct {
	Name                    string `toml:"name"`
	URL                     string `toml:"url"`
	Path                    string `toml:"path,omitempty"`
	Filename                string `toml:"filename,omitempty"`
	Ref                     string `toml:"ref,omitempty"`
	Priority                int    `toml:"priority,omitempty"`
	PrefixDuplicateProfiles bool   `toml:"prefixDuplicateProfiles,omitempty"`
	PrefixAllProfiles       bool   `toml:"prefixAllProfiles,omitempty"`
	Type                    string `toml:"type,omitempty"`
}

type AWSSSOConfiguration struct {
	StartURL            string
	SSORegion           string
	Prefix              string
	NoCredentialProcess bool
	ProfileTemplate     string
}

// NewDefaultConfig returns a config with OS specific defaults populated
func NewDefaultConfig() Config {
	// macos devices should default to the keychain backend
	if runtime.GOOS == "darwin" {
		keychain := "keychain"
		return Config{
			Keyring: &KeyringConfig{
				Backend: &keychain,
			},
		}
	}
	return Config{}
}

// checks and or creates the config folder on startup
func SetupConfigFolder() error {
	grantedFolder, err := GrantedConfigFolder()
	if err != nil {
		return err
	}
	if _, err := os.Stat(grantedFolder); os.IsNotExist(err) {
		err := os.Mkdir(grantedFolder, 0700)
		if err != nil {
			return err
		}
	}
	return nil
}

// checks and or creates the config folder on startup
func SetupZSHAutoCompleteFolderAssume() (string, error) {
	grantedFolder, err := GrantedConfigFolder()
	if err != nil {
		return "", err
	}
	zshPath := path.Join(grantedFolder, "zsh_autocomplete")
	if _, err := os.Stat(zshPath); os.IsNotExist(err) {
		err := os.Mkdir(zshPath, 0700)
		if err != nil {
			return "", err
		}
	}
	zshPath = path.Join(zshPath, build.AssumeScriptName())
	if _, err := os.Stat(zshPath); os.IsNotExist(err) {
		err := os.Mkdir(zshPath, 0700)
		if err != nil {
			return "", err
		}
	}
	return zshPath, nil
}

// checks and or creates the config folder on startup
func SetupZSHAutoCompleteFolderGranted() (string, error) {
	grantedFolder, err := GrantedConfigFolder()
	if err != nil {
		return "", err
	}
	zshPath := path.Join(grantedFolder, "zsh_autocomplete")
	if _, err := os.Stat(zshPath); os.IsNotExist(err) {
		err := os.Mkdir(zshPath, 0700)
		if err != nil {
			return "", err
		}
	}
	zshPath = path.Join(zshPath, build.GrantedBinaryName())
	if _, err := os.Stat(zshPath); os.IsNotExist(err) {
		err := os.Mkdir(zshPath, 0700)
		if err != nil {
			return "", err
		}
	}
	return zshPath, nil
}

func GrantedConfigFolder() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	configDir := filepath.Join(home, build.ConfigFolderName)
	if xdgConfigDir := os.Getenv("XDG_CONFIG_HOME"); !pathExists(configDir) && xdgConfigDir != "" {
		configDir = filepath.Join(xdgConfigDir, "granted")
	}

	return configDir, nil
}

func GrantedConfigFilePath() (string, error) {
	grantedFolder, err := GrantedConfigFolder()
	if err != nil {
		return "", err
	}
	configFilePath := path.Join(grantedFolder, "config")
	return configFilePath, nil
}

func GrantedCacheFolder() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	cacheDir := filepath.Join(home, build.ConfigFolderName)
	if xdgCacheDir := os.Getenv("XDG_CACHE_HOME"); !pathExists(cacheDir) && xdgCacheDir != "" {
		cacheDir = filepath.Join(xdgCacheDir, "granted")
	}

	return cacheDir, nil
}

func GrantedStateFolder() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	stateDir := filepath.Join(home, build.ConfigFolderName)
	if xdgStateDir := os.Getenv("XDG_STATE_HOME"); !pathExists(stateDir) && xdgStateDir != "" {
		stateDir = filepath.Join(xdgStateDir, "granted")
	}

	return stateDir, nil
}

// GrantedFolders creates a slice of directories created during installation and removes duplicates
func GrantedFolders() ([]string, error) {
	var grantedDirs []string
	configDir, _ := GrantedConfigFolder()
	cacheDir, _ := GrantedCacheFolder()
	stateDir, _ := GrantedStateFolder()
	grantedDirs = append(grantedDirs, configDir)
	grantedDirs = append(grantedDirs, cacheDir)
	grantedDirs = append(grantedDirs, stateDir)

	grantedDirs = slices.Compact(grantedDirs)

	return grantedDirs, nil
}

// pathExists checks if a given file exists and returns true or false
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func Load() (*Config, error) {
	configFilePath, err := GrantedConfigFilePath()
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(configFilePath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	c := NewDefaultConfig()

	_, err = toml.NewDecoder(file).Decode(&c)
	if err != nil {
		// if there is an error just reset the file
		return nil, err
	}
	return &c, nil
}

func (c *Config) Save() error {
	configFilePath, err := GrantedConfigFilePath()
	if err != nil {
		return err
	}

	file, err := os.OpenFile(configFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	return toml.NewEncoder(file).Encode(c)
}
