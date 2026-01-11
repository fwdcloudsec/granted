package registry

import (
	"errors"
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/granted/awsmerge"
	"github.com/fwdcloudsec/granted/pkg/granted/registry/gitregistry"
	"github.com/fwdcloudsec/granted/pkg/testable"

	"github.com/urfave/cli/v2"
)

const (
	// permission for user to read/write/execute.
	USER_READ_WRITE_PERM = 0700
)

var AddCommand = cli.Command{
	Name:        "add",
	Description: "Add a Profile Registry that you want to sync with aws config file",
	Usage:       "Provide git repository you want to sync with aws config file",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "name", Required: true, Usage: "A unique name for the profile registry", Aliases: []string{"n"}},
		&cli.StringFlag{Name: "url", Required: true, Usage: "The URL for the registry", Aliases: []string{"u"}},
		&cli.StringFlag{Name: "path", Usage: "For git registries: provide path if only the subfolder needs to be synced", Aliases: []string{"p"}},
		&cli.StringFlag{Name: "filename", Aliases: []string{"f"}, Usage: "For git registries:  provide filename if yml file is not granted.yml", DefaultText: "granted.yml"},
		&cli.IntFlag{Name: "priority", Usage: "The priority for the profile registry", Value: 0},
		&cli.StringFlag{Name: "ref", Usage: "Git ref (branch, tag, or commit) to checkout"},
		&cli.BoolFlag{Name: "prefix-all-profiles", Aliases: []string{"pap"}, Usage: "Provide this flag if you want to append registry name to all profiles"},
		&cli.BoolFlag{Name: "prefix-duplicate-profiles", Aliases: []string{"pdp"}, Usage: "Provide this flag if you want to append registry name to duplicate profiles"},
		&cli.BoolFlag{Name: "write-on-sync-failure", Aliases: []string{"wosf"}, Usage: "Always overwrite AWS config, even if sync fails (DEPRECATED)"},
		&cli.StringSliceFlag{Name: "required-key", Aliases: []string{"r", "requiredKey"}, Usage: "Used to bypass the prompt or override user specific values"},
		&cli.StringFlag{Name: "type", Value: "git", Usage: "specify the type of granted registry source you want to set up. Default: git"}},

	ArgsUsage: "--name <registry_name> --url <repository_url> --type <registry_type>",
	Action: func(c *cli.Context) error {
		ctx := c.Context

		gConf, err := grantedConfig.Load()
		if err != nil {
			return err
		}

		if c.Bool("write-on-sync-failure") {
			return errors.New("'--write-on-sync-failure' has been deprecated. Please raise an issue if this has affected your workflows: https://github.com/fwdcloudsec/granted/issues/new")
		}

		name := c.String("name")
		URL := c.String("url")
		pathFlag := c.String("path")
		configFileName := c.String("filename")
		ref := c.String("ref")
		prefixAllProfiles := c.Bool("prefix-all-profiles")
		prefixDuplicateProfiles := c.Bool("prefix-duplicate-profiles")
		requiredKey := c.StringSlice("required-key")
		priority := c.Int("priority")
		registryType := c.String("type")

		if registryType == "http" {
			return fmt.Errorf("HTTP registries are not longer supported in this version of Granted: if you are impacted by this please raise an issue: https://github.com/fwdcloudsec/granted/issues/new")
		}

		if registryType != "git" {
			return fmt.Errorf("invalid registry type provided: %s. must be 'git'", c.String("type"))
		}

		for _, r := range gConf.ProfileRegistry.Registries {
			if r.Name == name {
				clio.Errorf("profile registry with name '%s' already exists. Name is required to be unique. Try adding with different name.\n", name)

				return nil
			}
		}

		registryConfig := grantedConfig.Registry{
			Name:                    name,
			URL:                     URL,
			Path:                    pathFlag,
			Filename:                configFileName,
			Ref:                     ref,
			Priority:                priority,
			PrefixDuplicateProfiles: prefixDuplicateProfiles,
			PrefixAllProfiles:       prefixAllProfiles,
			Type:                    registryType,
		}

		registry, err := gitregistry.New(gitregistry.Opts{
			Name:         name,
			URL:          URL,
			Path:         pathFlag,
			Filename:     configFileName,
			Ref:          ref,
			RequiredKeys: requiredKey,
			Interactive:  true,
		})

		if err != nil {
			return err
		}
		src, err := registry.AWSProfiles(ctx, true)
		if err != nil {
			return err
		}

		dst, filepath, err := loadAWSConfigFile()
		if err != nil {
			return err
		}

		merged, err := awsmerge.WithRegistry(src, dst, awsmerge.RegistryOpts{
			Name:                    name,
			PrefixAllProfiles:       prefixAllProfiles,
			PrefixDuplicateProfiles: prefixDuplicateProfiles,
		})
		var dpe awsmerge.DuplicateProfileError
		if errors.As(err, &dpe) {
			clio.Warnf(err.Error())

			const (
				DUPLICATE = "Add registry name as prefix to all duplicate profiles for this registry"
				ABORT     = "Abort, I will manually fix this"
			)

			options := []string{DUPLICATE, ABORT}

			in := survey.Select{Message: "Please select which option would you like to choose to resolve: ", Options: options}
			var selected string
			err = testable.AskOne(&in, &selected)
			if err != nil {
				return err
			}

			if selected == ABORT {
				return fmt.Errorf("aborting sync for registry %s", name)
			}

			registryConfig.PrefixDuplicateProfiles = true

			// try and merge again
			merged, err = awsmerge.WithRegistry(src, dst, awsmerge.RegistryOpts{
				Name:                    name,
				PrefixAllProfiles:       prefixAllProfiles,
				PrefixDuplicateProfiles: true,
			})
			if err != nil {
				return fmt.Errorf("error after trying to merge profiles again: %w", err)
			}
		}

		// we have verified that this registry is a valid one and sync is completed.
		// so save the new registry to config file.
		gConf.ProfileRegistry.Registries = append(gConf.ProfileRegistry.Registries, registryConfig)
		err = gConf.Save()
		if err != nil {
			return err
		}

		err = merged.SaveTo(filepath)
		if err != nil {
			return err
		}

		return nil
	},
}