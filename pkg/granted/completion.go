package granted

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"os"
	"os/user"
	"path"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/internal/build"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/shells"
	"github.com/urfave/cli/v2"
)

//go:embed templates
var templateFiles embed.FS
var flags = []cli.Flag{
	&cli.StringFlag{
		Name:     "shell",
		Aliases:  []string{"s"},
		Usage:    "Shell to install completions for (fish, zsh, tcsh, bash)",
		Required: true,
	},
}

var CompletionCommand = cli.Command{
	Name:  "completion",
	Usage: "Add autocomplete to your granted cli installation",
	Flags: flags,
	Action: func(c *cli.Context) (err error) {
		shell := c.String("shell")
		switch shell {
		case "fish":
			err = installFishCompletions(c)
		case "zsh":
			err = installZSHCompletions(c)
		case "tcsh":
			err = installTcshCompletions(c)
		case "bash":
			err = installBashCompletions(c)
		default:
			clio.Info("To install completions for other shells, please see our docs: https://docs.commonfate.io/granted/configuration#autocompletion")
		}
		return err
	},

	Description: "Install completions for fish, zsh, or bash. To install completions for other shells, please see our docs:\nhttps://docs.commonfate.io/granted/configuration#autocompletion\n",
}

func installFishCompletions(c *cli.Context) error {
	tmpl, err := template.ParseFS(templateFiles, "templates/*")
	if err != nil {
		return err
	}

	assumeData := AutoCompleteTemplateData{
		Program: build.AssumeScriptName(),
	}
	assumeBuf := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(assumeBuf, "fish_autocomplete_assume.tmpl", assumeData)
	if err != nil {
		return err
	}

	grantedData := AutoCompleteTemplateData{
		Program: build.GrantedBinaryName(),
	}
	grantedBuf := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(grantedBuf, "fish_autocomplete_granted.tmpl", grantedData)
	if err != nil {
		return err
	}

	// try to fetch user home dir
	usr, _ := user.Current()
	completionsDir := path.Join(usr.HomeDir, ".config/fish/completions")

	// ensure the completions directory exists
	err = os.MkdirAll(completionsDir, 0755)
	if err != nil {
		return fmt.Errorf("something went wrong when creating fish completions directory: %s", err.Error())
	}

	assumeFile := path.Join(completionsDir, fmt.Sprintf("%s.fish", assumeData.Program))
	err = os.WriteFile(assumeFile, assumeBuf.Bytes(), 0600)
	if err != nil {
		return fmt.Errorf("something went wrong when saving fish autocompletions: %s", err.Error())
	}

	grantedFile := path.Join(completionsDir, fmt.Sprintf("%s.fish", grantedData.Program))
	err = os.WriteFile(grantedFile, grantedBuf.Bytes(), 0600)
	if err != nil {
		return fmt.Errorf("something went wrong when saving fish autocompletions: %s", err.Error())
	}

	clio.Success("Fish autocompletions generated successfully")
	clio.Info("To use these completions please run:")
	clio.Infof("source %s", assumeFile)
	clio.Infof("source %s", grantedFile)
	return nil
}

type AutoCompleteTemplateData struct {
	Program string
}

func installZSHCompletions(c *cli.Context) error {
	file, err := shells.GetZshConfigFile()
	if err != nil {
		return err
	}

	tmpl, err := template.ParseFS(templateFiles, "templates/*")
	if err != nil {
		return err
	}

	assumeData := AutoCompleteTemplateData{
		Program: build.AssumeScriptName(),
	}
	assume := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(assume, "zsh_autocomplete_assume.tmpl", assumeData)
	if err != nil {
		return err
	}
	grantedData := AutoCompleteTemplateData{
		Program: build.GrantedBinaryName(),
	}
	granted := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(granted, "zsh_autocomplete_granted.tmpl", grantedData)
	if err != nil {
		return err
	}

	zshPathAssume, err := config.SetupZSHAutoCompleteFolderAssume()
	if err != nil {
		return err
	}

	err = os.WriteFile(path.Join(zshPathAssume, "_"+assumeData.Program), assume.Bytes(), 0666)
	if err != nil {
		return err
	}
	zshPathGranted, err := config.SetupZSHAutoCompleteFolderGranted()
	if err != nil {
		return err
	}
	err = os.WriteFile(path.Join(zshPathGranted, "_"+grantedData.Program), granted.Bytes(), 0666)
	if err != nil {
		return err
	}
	err = shells.AppendLine(file, fmt.Sprintf("fpath=(%s/ $fpath)", zshPathAssume))
	var lae *shells.ErrLineAlreadyExists
	if is := errors.As(err, &lae); err != nil && !is {
		return err
	}
	err = shells.AppendLine(file, fmt.Sprintf("fpath=(%s/ $fpath)", zshPathGranted))
	lae = nil
	if is := errors.As(err, &lae); err != nil && !is {
		return err
	}
	clio.Success("ZSH autocompletions generated successfully")
	clio.Warn("A shell restart is required to apply changes, please open a new terminal to test that autocomplete is working")
	return nil
}

func installBashCompletions(c *cli.Context) error {
	clio.Info("We don't have completion support for bash yet, check out our docs to find out how to let us know you want this feature https://granted.dev/autocompletion")
	return nil
}

func installTcshCompletions(c *cli.Context) error {
	clio.Info("We don't have completion support for tcsh yet, check out our docs to find out how to let us know you want this feature https://granted.dev/autocompletion")
	return nil
}
