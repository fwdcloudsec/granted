package launcher

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/fwdcloudsec/granted/pkg/config"
)

type TemplateData struct {
	Profile string
	URL     string
	Args    map[string]string
}

type Custom struct {
	// Command to execute. The command is a series of arguments which may include templated variables.
	// For example: '/usr/bin/firefox --new-tab --profile={{.Profile}} --url={{.URL}}'
	Command     string
	ForkProcess bool

	// TemplateArgs are additional custom arguments which are provided by specifying
	// --browser-template-argument key=value when calling Granted.
	//
	// These arguments are available for use when creating the browser template to launch.
	TemplateArgs map[string]string
}

func (l Custom) LaunchCommand(url string, profile string) ([]string, error) {
	if l.Command == "" {
		// the command must always be specified, so return an error here
		return nil, errors.New("the command template was empty - ensure that a browser launch template 'Command' field is specified in your Granted config")
	}

	tmpl := template.New("")
	tmpl, err := tmpl.Parse(l.Command)
	if err != nil {
		return nil, fmt.Errorf("parsing command template (check that your browser launch template is valid in your Granted config): %w", err)
	}

	data := TemplateData{
		Profile: profile,
		URL:     url,
		Args:    l.TemplateArgs,
	}

	var renderedCommand strings.Builder
	err = tmpl.Execute(&renderedCommand, data)
	if err != nil {
		return nil, fmt.Errorf("executing command template (check that your browser launch template is valid in your Granted config): %w", err)
	}

	commandParts := splitCommand(renderedCommand.String())
	return commandParts, nil
}

// splits each component of the command. Anything within quotes will be handled as one component of the command
// eg open -a "Google Chrome" <URL> returns ["open", "-a", "Google Chrome", "<URL>"]
func splitCommand(command string) []string {

	re := regexp.MustCompile(`"([^"]+)"|(\S+)`)
	matches := re.FindAllStringSubmatch(command, -1)

	var result []string
	for _, match := range matches {

		if match[1] != "" {
			result = append(result, match[1])
		} else {

			result = append(result, match[2])
		}
	}

	return result
}

func (l Custom) UseForkProcess() bool { return l.ForkProcess }

var ErrLaunchTemplateNotConfigured = errors.New("launch template is not configured")

// CustomFromLaunchTemplate creates a custom browser launcher from a configuration launch template.
//
// It prevents a panic if the launch template is nil.
func CustomFromLaunchTemplate(lt *config.BrowserLaunchTemplate, args []string) (Custom, error) {
	if lt == nil {
		return Custom{}, ErrLaunchTemplateNotConfigured
	}

	templateArgs := make(map[string]string)
	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			return Custom{}, fmt.Errorf("invalid argument format: %s", arg)
		}
		templateArgs[parts[0]] = parts[1]
	}

	return Custom{
		Command:      lt.Command,
		TemplateArgs: templateArgs,
		ForkProcess:  lt.UseForkProcess,
	}, nil
}
