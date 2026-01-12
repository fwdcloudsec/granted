// Package alias sets up the shell alias for Granted.
// The alias is required so that the Granted wrapper script
// (scripts/granted in this repository) is sourced rather than executed.
// By sourcing the wrapper script we can export environment variables into
// the user's shell after they call the Granted CLI.
// These variables are typically used for cloud provider session credentials.
package alias

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/internal/build"
	"github.com/fwdcloudsec/granted/pkg/shells"
	"github.com/fatih/color"
)

func init() {
	// By default the shell wrapper makes the color library
	// think that the terminal doesn't support colors.
	// We override this behaviour here so that we can print colored output.
	// Users can set NO_COLOR to true if they are working in a terminal without
	// color support and want to use Granted there.
	_, clio.NoColor = os.LookupEnv("NO_COLOR")
	_, color.NoColor = os.LookupEnv("NO_COLOR")
}

const fishAlias = `alias assume="source /usr/local/bin/assume.fish"`
const tcshAlias = `alias assume 'source /usr/local/bin/assume.tcsh'`

const defaultAlias = `alias assume=". assume"`
const fishAliasBrew = `alias assume="source (brew --prefix)/bin/assume.fish"`
const tcshAliasBrew = `alias assume 'source (brew --prefix)/bin/assume.tcsh'`

const devFishAlias = `alias dassume="source /usr/local/bin/dassume.fish"`
const devTcshAlias = `alias dassume 'source /usr/local/bin/dassume.tcsh'`
const devDefaultAlias = `alias dassume=". dassume"`

func GetDefaultAlias() string {
	if build.IsDev() {
		return devDefaultAlias
	}
	return defaultAlias
}
func GetFishAlias() string {
	if build.IsDev() {
		return devFishAlias
	}

	// if 'brew' exists on the path, use the brew prefix rather than /usr/local/bin when installing the alias.
	// chrnorm: there's not really a better way to determine if we've been installed with brew or not.
	if _, err := exec.LookPath("brew"); err == nil {
		return fishAliasBrew
	}

	return fishAlias
}
func GetTcshAlias() string {
	if build.IsDev() {
		return devTcshAlias
	}

	// if 'brew' exists on the path, use the brew prefix rather than /usr/local/bin when installing the alias.
	// chrnorm: there's not really a better way to determine if we've been installed with brew or not.
	if _, err := exec.LookPath("brew"); err == nil {
		return tcshAliasBrew
	}

	return tcshAlias
}

type Config struct {
	File  string
	Alias string
}

// IsConfigured returns whether the shell alias is correctly set up
// for Granted.
func IsConfigured() bool {
	return os.Getenv("GRANTED_ALIAS_CONFIGURED") == "true"
}

// MustBeConfigured displays a helpful error message and exits the CLI
// if the alias is detected as not being configured properly.
func MustBeConfigured(autoConfigure bool) error {
	if !IsConfigured() {
		return SetupShellWizard(autoConfigure)
	}
	return nil
}

// GetShellFromShellEnv returns the shell from the SHELL environment variable
func GetShellFromShellEnv(shellEnv string) (string, error) {
	if strings.Contains(shellEnv, "fish") {
		return "fish", nil

	} else if strings.Contains(shellEnv, "bash") {
		return "bash", nil

	} else if strings.Contains(shellEnv, "zsh") {
		return "zsh", nil
	} else if strings.Contains(shellEnv, "tcsh") {
		return "tcsh", nil
	} else if strings.Contains(shellEnv, "sh") {
		// Fallback to POSIX
		return "posix", nil
	} else {
		return "", fmt.Errorf("we couldn't detect your shell type (%s). Please follow the steps at https://docs.commonfate.io/granted/internals/shell-alias to assume roles with Granted", shellEnv)
	}
}

// GetShellAlias returns the alias config for a shell
func GetShellAlias(shell string) (Config, error) {
	var file string
	var err error
	alias := GetDefaultAlias()
	switch shell {
	case "fish":
		file, err = shells.GetFishConfigFile()
		alias = GetFishAlias()
	case "bash":
		file, err = shells.GetBashConfigFile()
	case "zsh":
		file, err = shells.GetZshConfigFile()
	case "tcsh":
		file, err = shells.GetTcshConfigFile()
		alias = GetTcshAlias()
	case "posix":
		file, err = shells.GetPosixConfigFile()
	default:
		err = &ErrShellNotSupported{Shell: shell}
	}
	if err != nil {
		return Config{}, err
	}
	return Config{File: file, Alias: alias}, nil
}

func SetupShellWizard(autoConfigure bool) error {
	// SHELL is set by the wrapper script
	shellEnv := os.Getenv("SHELL")
	shell, err := GetShellFromShellEnv(shellEnv)
	if err != nil {
		return err
	}
	cfg, err := GetShellAlias(shell)
	if err != nil {
		return err
	}

	// skip prompt if autoConfigure is set to true
	if !autoConfigure {
		clio.Info("To assume roles with Granted, we need to add an alias to your shell profile (https://docs.commonfate.io/granted/internals/shell-alias)")
		withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
		in := &survey.Confirm{
			Message: fmt.Sprintf("Install %s alias at %s", shell, cfg.File),
			Default: true,
		}
		var confirm bool
		err = survey.AskOne(in, &confirm, withStdio)
		if err != nil {
			return err
		}

		if !confirm {
			return errors.New("cancelled alias installation")
		}

		clio.NewLine()
	}

	err = Install(cfg)
	if err != nil {
		return err
	}
	clio.Successf("Added the Granted alias to %s", cfg.File)
	clio.Warn("Shell restart required to apply changes: please open a new terminal window and re-run your command.")
	os.Exit(0)
	return nil
}

type UninstallShellResults struct {
	ConfigFile string
}

// UninstallDefaultShellAlias tries to uninstall the Granted aliases from the
// user's default shell bindings
func UninstallDefaultShellAlias() error {
	// SHELL is set by the wrapper script
	shellEnv := os.Getenv("SHELL")
	shell, err := GetShellFromShellEnv(shellEnv)
	if err != nil {
		return fmt.Errorf("we couldn't detect your shell type (%s). You may need to manually removed Granted's aliases from your shell configuration", shellEnv)
	}
	cfg, err := GetShellAlias(shell)
	if err != nil {
		return err
	}
	err = Uninstall(cfg)
	if err != nil {
		return err
	}
	clio.Successf("Removed the Granted alias from %s", cfg.File)
	return nil
}

// Install the Granted alias to a config file for a specified shell.
func Install(cfg Config) error {
	err := shells.AppendLine(cfg.File, cfg.Alias)
	var aee *shells.ErrLineAlreadyExists
	if errors.As(err, &aee) {
		return &ErrAlreadyInstalled{File: cfg.File}
	}
	return err
}

// Uninstall the Granted alias to a config file for a specified shell.
func Uninstall(cfg Config) error {
	err := shells.RemoveLine(cfg.File, cfg.Alias)
	var aee *shells.ErrLineAlreadyExists
	if errors.As(err, &aee) {
		return &ErrNotInstalled{File: cfg.File}
	}
	return err
}
