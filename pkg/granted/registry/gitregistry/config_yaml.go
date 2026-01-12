package gitregistry

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"gopkg.in/yaml.v3"
)

type ConfigYAML struct {
	AwsConfigPaths []string                         `yaml:"awsConfig"`
	TemplateValues []map[string][]map[string]string `yaml:"templateValues"`
}

// parseGrantedYAML unmarshals a 'granted.yml' file contained in the git profile registry.
func (p Registry) parseGrantedYAML() (*ConfigYAML, error) {
	fileName := "granted.yml"

	if p.opts.Filename != "" {
		fileName = p.opts.Filename
	}

	dirPath := p.clonedTo

	if p.opts.Path != "" {
		dirPath = path.Join(dirPath, p.opts.Path)
	}

	filepath := path.Join(dirPath, fileName)

	clio.Debugf("verifying if valid config exists in %s", filepath)
	file, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var cfg ConfigYAML

	err = yaml.Unmarshal(file, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

// granted.yml config might contain user specific variables
// in such case we would prompt users to add them before registry is added.
func (c ConfigYAML) PromptRequiredKeys(passedKeys []string, interactive bool, registryName string) error {
	var requiredKeysThroughFlags = make(map[string]string)

	gConf, err := grantedConfig.Load()
	if err != nil {
		return err
	}

	for _, v := range c.TemplateValues {
		for fieldName, values := range v {
			if isRequiredKey(values) {

				var questions []*survey.Question
				if len(passedKeys) != 0 {
					for _, val := range passedKeys {
						key, value, err := formatKey(val)
						if err != nil {
							return err
						}

						requiredKeysThroughFlags[key] = value
					}
				}

				// if the key was passed through cli then skip the prompt
				if _, ok := requiredKeysThroughFlags[fieldName]; ok {
					err := SaveKey(gConf, fieldName, requiredKeysThroughFlags[fieldName])
					if err != nil {
						return err
					}

					break
				}

				// if the key is already configured then skip
				if gConf.ProfileRegistry.RequiredKeys[fieldName] != "" {
					clio.Debugf("%s is already configured so skipping", fieldName)

					break
				}

				// if the required key is missing and the command is called through credential process
				// then instead of asking for prompt we need to fail the process because
				// credential process might be used with native the AWS CLI command which can't have any thing
				// in its STDIO except the JSON output that AWS credential_process expects.
				// so fail with warning that there are required keys you need to fill by running granted sync.
				if !interactive {
					clio.Errorf("Error syncing registry '%s'. You need to enter value for required key: '%s' before you can preceed.", registryName, fieldName)
					clio.Errorf("run 'granted registry sync' to enter value for the required key")

					return fmt.Errorf("sync failed")
				}

				var prompt string
				for _, j := range values {
					for k, v := range j {
						if k == "prompt" {
							prompt = v
						}
					}
				}

				withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)

				qs := survey.Question{
					Name:     fieldName,
					Prompt:   &survey.Input{Message: fmt.Sprintf("'%s': %s", fieldName, prompt)},
					Validate: survey.Required}

				questions = append(questions, &qs)
				ansmap := make(map[string]interface{})

				if len(questions) > 0 {
					clio.Info("Your Profile Registry requires you to input values for the following keys:")

					err = survey.Ask(questions, &ansmap, withStdio)
					if err != nil {
						return err
					}

					err = SaveKeys(gConf, ansmap)
					if err != nil {
						return err
					}

					break
				}

			} else {
				// for all other variables add them to registry as variables
				for _, j := range values {
					for k, v := range j {
						if k == "value" {
							if gConf.ProfileRegistry.Variables == nil {
								gConf.ProfileRegistry.Variables = make(map[string]string)
								gConf.ProfileRegistry.Variables[fieldName] = v
							} else {
								gConf.ProfileRegistry.Variables[fieldName] = v
							}
							err := gConf.Save()
							if err != nil {
								return err
							}

							break

						}
					}
				}
			}
		}
	}

	return nil
}

// This is used when user enters the required key through cli prompts.
func SaveKeys(gConf *grantedConfig.Config, ansmap map[string]interface{}) error {
	for k, v := range ansmap {
		if len(gConf.ProfileRegistry.RequiredKeys) == 0 {
			var requiredKeys = make(map[string]string)
			requiredKeys[k] = v.(string)
			gConf.ProfileRegistry.RequiredKeys = requiredKeys
		} else {
			gConf.ProfileRegistry.RequiredKeys[k] = v.(string)
		}
	}

	err := gConf.Save()
	if err != nil {
		return err
	}

	return nil
}

// This is used when user passed the required value through flag.
func SaveKey(gConf *grantedConfig.Config, key string, value string) error {
	if len(gConf.ProfileRegistry.RequiredKeys) == 0 {
		var requiredKeys = make(map[string]string)
		requiredKeys[key] = value
		gConf.ProfileRegistry.RequiredKeys = requiredKeys
	} else {
		gConf.ProfileRegistry.RequiredKeys[key] = value
	}

	err := gConf.Save()
	if err != nil {
		return err
	}

	return nil
}

// isRequiredKey has user specific keys that if true
// will prompt users to enter value for them
func isRequiredKey(m []map[string]string) bool {
	for _, fields := range m {
		for k, v := range fields {
			if k == "isRequired" && v == "true" {
				return true
			}
		}
	}
	return false
}

// Get the key=value from the provided required variable flag.
func formatKey(s string) (string, string, error) {
	value := strings.Split(s, "=")
	if len(value) == 2 {
		return value[0], value[1], nil
	}

	return "", "", fmt.Errorf("invalid value '%s'provided for the required key", s)
}
