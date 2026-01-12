package granted

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/core"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"gopkg.in/ini.v1"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/internal/build"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/fwdcloudsec/granted/pkg/testable"
	"github.com/urfave/cli/v2"
)

var CredentialsCommand = cli.Command{
	Name:        "credentials",
	Usage:       "Manage secure IAM credentials",
	Subcommands: []*cli.Command{&AddCredentialsCommand, &ImportCredentialsCommand, &UpdateCredentialsCommand, &ListCredentialsCommand, &RemoveCredentialsCommand, &ExportCredentialsCommand, &RotateCredentialsCommand, &ImportCredFromEnvCommand},
}

var AddCredentialsCommand = cli.Command{
	Name:      "add",
	Usage:     "Add IAM credentials to secure storage",
	ArgsUsage: "[<profile>]",
	Action: func(c *cli.Context) error {
		profileName := c.Args().First()
		if profileName == "" {
			in := survey.Input{Message: "Profile Name:"}
			err := testable.AskOne(&in, &profileName, survey.WithValidator(survey.MinLength(1)))
			if err != nil {
				return err
			}
		}

		// validate the the profile does not already exist
		profiles, err := cfaws.LoadProfiles()
		if err != nil {
			return err
		}
		if profiles.HasProfile(profileName) {
			return fmt.Errorf("a profile with name %s already exists, you can import an existing profile using '%s credentials import %s", profileName, build.GrantedBinaryName(), profileName)
		}

		credentials, err := promptCredentials()
		if err != nil {
			return err
		}

		// store the credentials in secure storage
		secureIAMCredentialStorage := securestorage.NewSecureIAMCredentialStorage()
		err = secureIAMCredentialStorage.StoreCredentials(profileName, credentials)
		if err != nil {
			return err
		}
		err = updateOrCreateProfileWithCredentialProcess(profileName)
		if err != nil {
			return err
		}
		fmt.Printf("Saved %s to secure storage\n", profileName)

		return nil
	},
}

// addCredentialProcessToConfigfileProfile creates or updates a profile entry in the aws config file with a granted credential_process entry
// this allows the profile to still work as expected with the AWS cli or other tools using the --profile flag
//
//	[profile my-profile]
//	credential_process = granted credential-process --profile=my-profile
func updateOrCreateProfileWithCredentialProcess(profileName string) error {
	configPath := cfaws.GetAWSConfigPath()
	configFile, err := ini.LoadSources(ini.LoadOptions{
		AllowNonUniqueSections:  false,
		SkipUnrecognizableLines: false,
		AllowNestedValues:       true,
	}, configPath)
	if err != nil {
		return err
	}
	sectionName := "profile " + profileName
	section, err := configFile.GetSection(sectionName)
	if err != nil {
		section, err = configFile.NewSection(sectionName)
		if err != nil {
			return err
		}
	}
	_, err = section.NewKey("credential_process", fmt.Sprintf("%s credential-process --profile=%s", build.GrantedBinaryName(), profileName))
	if err != nil {
		return err
	}
	return configFile.SaveTo(configPath)
}

func validateProfileForImport(ctx context.Context, profiles *cfaws.Profiles, profileName string, overwrite bool) error {
	secureIAMCredentialStorage := securestorage.NewSecureIAMCredentialStorage()
	if !profiles.HasProfile(profileName) {
		return fmt.Errorf("profile with name %s does not exist", profileName)
	}

	profile, err := profiles.LoadInitialisedProfile(ctx, profileName)
	if err != nil {
		return err
	}

	// ensure that the profile is an IAM profile
	if profile.ProfileType != "AWS_IAM" {
		return fmt.Errorf("profile %s does not have related IAM credentials", profileName)
	}
	// ensure that it is a root profile
	if len(profile.Parents) != 0 {
		return fmt.Errorf("profile %s uses a source_profile you should import the root profile '%s' instead. '%s credentials import %s'", profileName, profile.Parents[0].Name, build.GrantedBinaryName(), profile.Parents[0].Name)
	}
	// ensure it does not already exist in the secure storage
	existsInSecureStorage, err := secureIAMCredentialStorage.SecureStorage.HasKey(profileName)
	if err != nil {
		return err
	}
	if existsInSecureStorage && !overwrite {
		return fmt.Errorf("profile %s is already stored in secure storage.\nIf you were trying to update the credentials in secure storage, you can use '%s credentials update %s', or to overwrite the credentials in secure storage, run '%s credentials import --overwrite %s'", profileName, build.GrantedBinaryName(), profileName, build.GrantedBinaryName(), profileName)
	}
	if !profile.AWSConfig.Credentials.HasKeys() {
		return fmt.Errorf("profile %s does not have IAM credentials configured", profileName)
	}
	return nil
}

var ImportCredentialsCommand = cli.Command{
	Name:      "import",
	Usage:     "Import plaintext IAM user credentials from AWS credentials file into secure storage",
	ArgsUsage: "[<profile>]",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "overwrite", Usage: "Overwrite an existing profile saved in secure storage with values from the AWS credentials file"},
	},
	Action: func(c *cli.Context) error {
		profileName := c.Args().First()
		profiles, err := cfaws.LoadProfiles()
		if err != nil {
			return err
		}

		if profileName == "" {
			in := survey.Select{Message: "Profile Name:", Options: profiles.ProfileNames}
			err := testable.AskOne(&in, &profileName, survey.WithValidator(func(ans interface{}) error {
				option := ans.(core.OptionAnswer)
				// Not all profiles are valid for importing, so ensure this profile is suitable, and inform the user if it is not + the reason
				return validateProfileForImport(c.Context, profiles, option.Value, c.Bool("overwrite"))
			}))
			if err != nil {
				return err
			}
		} else {
			err = validateProfileForImport(c.Context, profiles, profileName, c.Bool("overwrite"))
			if err != nil {
				return err
			}
		}

		profile, err := profiles.LoadInitialisedProfile(c.Context, profileName)
		if err != nil {
			return err
		}
		secureIAMCredentialStorage := securestorage.NewSecureIAMCredentialStorage()
		err = secureIAMCredentialStorage.StoreCredentials(profileName, profile.AWSConfig.Credentials)
		if err != nil {
			return err
		}
		// configure a profile in the config file with a credential process so the secure IAM credentials can be used
		err = updateOrCreateProfileWithCredentialProcess(profileName)
		if err != nil {
			return err
		}

		// remove the profile from the credentials file
		credentialsFilePath := cfaws.GetAWSCredentialsPath()
		credentialsFile, err := ini.LoadSources(ini.LoadOptions{
			AllowNonUniqueSections:  false,
			SkipUnrecognizableLines: false,
			AllowNestedValues:       true,
		}, credentialsFilePath)
		if err != nil {
			return err
		}

		items, err := credentialsFile.GetSection(profileName)
		if err != nil {
			return err
		}

		configPath := cfaws.GetAWSConfigPath()
		configFile, err := ini.LoadSources(ini.LoadOptions{
			AllowNonUniqueSections:  false,
			SkipUnrecognizableLines: false,
			AllowNestedValues:       true,
		}, configPath)
		if err != nil {
			return err
		}
		sectionName := "profile " + profileName

		// Merge options from the credentials profile to the config file profile.
		// if the same option is configured in the config file profile it takes precedence
		for _, key := range items.Keys() {
			// omit sensitive values from the merge
			if key.Name() != "aws_access_key_id" && key.Name() != "aws_secret_access_key" && key.Name() != "aws_session_token" {
				section, err := configFile.GetSection(sectionName)
				if err != nil {
					return err
				}
				if !section.HasKey(key.Name()) {
					_, err = section.NewKey(key.Name(), key.Value())
					if err != nil {
						return err
					}
				}
			}
		}
		// save the updated config file after merging
		err = configFile.SaveTo(configPath)
		if err != nil {
			return err
		}

		// remove the plaintext profile from the credentials file
		credentialsFile.DeleteSection(profileName)
		err = credentialsFile.SaveTo(credentialsFilePath)
		if err != nil {
			return err
		}
		fmt.Printf("Saved %s to secure storage\n", profileName)

		return nil
	},
}

func promptCredentials() (credentials aws.Credentials, err error) {
	in1 := survey.Input{Message: "Access Key ID:"}
	err = testable.AskOne(&in1, &credentials.AccessKeyID)
	if err != nil {
		return
	}
	in2 := survey.Password{Message: "Secret Access Key:"}
	err = testable.AskOne(&in2, &credentials.SecretAccessKey)
	if err != nil {
		return
	}
	return
}

var UpdateCredentialsCommand = cli.Command{
	Name:      "update",
	Usage:     "Update existing credentials in secure storage",
	ArgsUsage: "[<profile>]",
	Action: func(c *cli.Context) error {
		profileName := c.Args().First()
		secureIAMCredentialStorage := securestorage.NewSecureIAMCredentialStorage()

		if profileName == "" {
			profileNames, err := secureIAMCredentialStorage.SecureStorage.ListKeys()
			if err != nil {
				return err
			}
			if profileName == "" && len(profileNames) == 0 {
				fmt.Println("No credentials in secure storage")
				return nil
			}
			in := survey.Select{Message: "Profile Name:", Options: profileNames}
			err = testable.AskOne(&in, &profileName)
			if err != nil {
				return err
			}
		}

		has, err := secureIAMCredentialStorage.SecureStorage.HasKey(profileName)
		if err != nil {
			return err
		}
		if !has {
			return fmt.Errorf("no credentials exist for %s in secure storage. If you wanted to add a new profile, run '%s credentials add'", profileName, build.GrantedBinaryName())
		}

		credentials, err := promptCredentials()
		if err != nil {
			return err
		}
		err = secureIAMCredentialStorage.StoreCredentials(profileName, credentials)
		if err != nil {
			return err
		}

		fmt.Printf("Updated %s in secure storage\n", profileName)

		return nil
	},
}

var ListCredentialsCommand = cli.Command{
	Name:  "list",
	Usage: "Lists the profile names for credentials in secure storage",
	Action: func(c *cli.Context) error {
		secureIAMCredentialStorage := securestorage.NewSecureIAMCredentialStorage()
		profiles, err := secureIAMCredentialStorage.SecureStorage.List()
		if err != nil {
			return err
		}
		if len(profiles) == 0 {
			clio.Info("No IAM user credentials stored in secure storage")
			return nil
		}
		for _, profile := range profiles {
			// print to os.stdout for scripting usage
			fmt.Printf("%s\n", profile.Key)
		}
		return nil
	},
}

var RemoveCredentialsCommand = cli.Command{
	Name:      "remove",
	Usage:     "Remove credentials from secure storage and an associated profile if it exists in the AWS config file",
	ArgsUsage: "[<profile>]",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "all", Aliases: []string{"a"}, Usage: "Remove all credentials from secure storage and an associated profile if it exists in the AWS config file"},
	},
	Action: func(c *cli.Context) error {
		secureIAMCredentialStorage := securestorage.NewSecureIAMCredentialStorage()
		configPath := cfaws.GetAWSConfigPath()
		configFile, err := ini.LoadSources(ini.LoadOptions{
			AllowNonUniqueSections:  false,
			SkipUnrecognizableLines: false,
			AllowNestedValues:       true,
		}, configPath)
		if err != nil {
			return err
		}
		profileName := c.Args().First()
		secureProfileKeys, err := secureIAMCredentialStorage.SecureStorage.ListKeys()
		if err != nil {
			return err
		}
		var profileNames []string
		if c.Bool("all") {
			profileNames = append(profileNames, secureProfileKeys...)
		} else {
			if profileName == "" && len(secureProfileKeys) == 0 {
				fmt.Println("No credentials in secure storage")
				return nil
			}
			if profileName == "" {
				in := survey.Select{Message: "Profile Name:", Options: secureProfileKeys}
				err = testable.AskOne(&in, &profileName)
				if err != nil {
					return err
				}
			}
			profileNames = append(profileNames, profileName)
		}
		fmt.Printf(`Removing credentials from secure storage will cause them to be permanently deleted.
To avoid losing your credentials you may first want to export them to plaintext using 'granted credentials export-plaintext <profile name>'
This command will remove a profile with the same name from the AWS config file if it has a 'credential_process = granted credential-process --profile=<profile name>'
If you have already used 'granted credentials export-plaintext <profile name>' to export the credentials, the profile will not be removed by this command.

`)
		var confirm bool
		s := &survey.Confirm{
			Message: "Are you sure you want to remove these credentials and profile from your AWS config?",
			Default: true,
		}
		err = survey.AskOne(s, &confirm)
		if err != nil {
			return err
		}
		if !confirm {
			fmt.Printf("Cancelled clearing credentials\n")
			return nil
		}

		for _, profileName := range profileNames {
			fmt.Printf("Removing %s credentials from secure storage\n", profileName)
			err = secureIAMCredentialStorage.SecureStorage.Clear(profileName)
			if err != nil {
				return err
			}
			sectionName := "profile " + profileName
			if section, _ := configFile.GetSection(sectionName); section != nil {
				if key, _ := section.GetKey("credential_process"); key != nil {
					if strings.HasPrefix(key.Value(), fmt.Sprintf("%s credential-process", build.GrantedBinaryName())) {
						fmt.Printf("Removing profile %s AWS config file\n", profileName)
						configFile.DeleteSection(sectionName)
					}
				}
			}
		}
		err = configFile.SaveTo(configPath)
		if err != nil {
			return err
		}
		fmt.Printf("Cleared credentials from secure storage\n")
		return nil
	},
}

var ExportCredentialsCommand = cli.Command{
	Name:      "export-plaintext",
	Usage:     "Export credentials from the secure storage to ~/.aws/credentials file in plaintext",
	ArgsUsage: "[<profile>]",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "all", Aliases: []string{"a"}, Usage: "export all credentials from secure storage in plaintext"},
	},
	Action: func(c *cli.Context) error {
		secureIAMCredentialStorage := securestorage.NewSecureIAMCredentialStorage()
		profileName := c.Args().First()
		secureProfileKeys, err := secureIAMCredentialStorage.SecureStorage.ListKeys()
		if err != nil {
			return err
		}
		var profileNames []string
		if c.Bool("all") {
			profileNames = append(profileNames, secureProfileKeys...)
		} else {
			if profileName == "" && len(secureProfileKeys) == 0 {
				fmt.Println("No credentials in secure storage")
				return nil
			}

			if profileName == "" {
				in := survey.Select{Message: "Profile Name:", Options: secureProfileKeys}
				err = testable.AskOne(&in, &profileName)
				if err != nil {
					return err
				}
			}
			profileNames = append(profileNames, profileName)
		}

		for _, profileName := range profileNames {
			credentials, err := secureIAMCredentialStorage.GetCredentials(profileName)
			if err != nil {
				return err
			}
			// fetch parsed credentials file
			credentialsFilePath := cfaws.GetAWSCredentialsPath()
			credentialsFile, err := ini.LoadSources(ini.LoadOptions{
				AllowNonUniqueSections:  false,
				SkipUnrecognizableLines: false,
				AllowNestedValues:       true,
			}, credentialsFilePath)
			if err != nil {
				return err
			}

			section, err := credentialsFile.NewSection(profileName)
			if err != nil {
				return err
			}
			err = section.ReflectFrom(&struct {
				AWSAccessKeyID     string `ini:"aws_access_key_id"`
				AWSSecretAccessKey string `ini:"aws_secret_access_key"`
				AWSSessionToken    string `ini:"aws_session_token,omitempty"`
			}{
				AWSAccessKeyID:     credentials.AccessKeyID,
				AWSSecretAccessKey: credentials.SecretAccessKey,
				AWSSessionToken:    credentials.SessionToken,
			})
			if err != nil {
				return err
			}
			err = credentialsFile.SaveTo(credentialsFilePath)
			if err != nil {
				return err
			}
			configPath := cfaws.GetAWSConfigPath()
			configFile, err := ini.LoadSources(ini.LoadOptions{
				AllowNonUniqueSections:  false,
				SkipUnrecognizableLines: false,
				AllowNestedValues:       true,
			}, configPath)
			if err != nil {
				return err
			}
			sectionName := "profile " + profileName
			if section, _ := configFile.GetSection(sectionName); section != nil {
				if section.HasKey("credential_process") {
					// if the result of removing the credential process is that the profile has no configuration, then just remove it completely.
					// the profile in the credential file will suffice
					// else just remove the credential process line.
					// this avoids leaving the config file with an empty profile, which appears to be some kind of error when its not
					if len(section.Keys()) > 1 {
						section.DeleteKey("credential_process")
					} else {
						configFile.DeleteSection(sectionName)
					}
					err = configFile.SaveTo(configPath)
					if err != nil {
						return err
					}

				}
			}

			fmt.Printf("Exported %s in plaintext from secure storage to %s\n", profileName, credentialsFilePath)
			fmt.Printf("The %s credentials have not been removed from secure storage. If you'd like to delete them, you can run '%s credentials remove %s'\n", profileName, build.GrantedBinaryName(), profileName)

		}
		return nil
	},
}

var RotateCredentialsCommand = cli.Command{
	Name:  "rotate",
	Usage: "Generates new access key for the profile in AWS, and updates the profile",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "profile", Usage: "If provided, generates new access key for the specified profile"},
		&cli.BoolFlag{Name: "delete", Usage: "delete the previous active key"},
	},
	Action: func(c *cli.Context) error {
		profileName := c.String("profile")

		secureIAMCredentialStorage := securestorage.NewSecureIAMCredentialStorage()

		if profileName == "" {
			profileNames, err := secureIAMCredentialStorage.SecureStorage.ListKeys()
			if err != nil {
				return err
			}
			if len(profileNames) == 0 {
				fmt.Println("No credentials in secure storage")
				return nil
			}
			in := survey.Select{Message: "Profile Name:", Options: profileNames}
			err = testable.AskOne(&in, &profileName)
			if err != nil {
				return err
			}
		}

		has, err := secureIAMCredentialStorage.SecureStorage.HasKey(profileName)
		if err != nil {
			return err
		}
		if !has {
			return fmt.Errorf("no credentials exist for %s in secure storage. If you wanted to add a new profile, run '%s credentials add'", profileName, build.GrantedBinaryName())
		}

		var t aws.Credentials
		err = secureIAMCredentialStorage.SecureStorage.Retrieve(profileName, &t)
		if err != nil {
			return err
		}

		opts := []func(*config.LoadOptions) error{
			// load the config profile
			config.WithSharedConfigProfile(profileName),
		}

		// load the creds from the credentials file
		cfg, err := config.LoadDefaultConfig(c.Context, opts...)
		if err != nil {
			return err
		}

		iamClient := iam.NewFromConfig(cfg)

		res, err := iamClient.CreateAccessKey(c.Context, &iam.CreateAccessKeyInput{})
		if err != nil {
			return err
		}

		err = secureIAMCredentialStorage.StoreCredentials(profileName, aws.Credentials{AccessKeyID: *res.AccessKey.AccessKeyId, SecretAccessKey: *res.AccessKey.SecretAccessKey})
		if err != nil {
			return err
		}

		_, err = iamClient.UpdateAccessKey(c.Context, &iam.UpdateAccessKeyInput{AccessKeyId: &t.AccessKeyID, Status: "Inactive"})
		if err != nil {
			return err
		}

		if c.Bool("delete") {
			_, err = iamClient.DeleteAccessKey(c.Context, &iam.DeleteAccessKeyInput{AccessKeyId: &t.AccessKeyID})
			if err != nil {
				return err
			}
		}

		clio.Successf("Access Key of '%s' profile has been successfully rotated and updated in secure storage\n", profileName)

		return nil
	},
}

var ImportCredFromEnvCommand = cli.Command{
	Name:  "import-from-env",
	Usage: "Create a new AWS config profile with IAM credentials imported from environment. You must have $AWS_ACCESS_KEY_ID and $AWS_SECRET_ACCESS_KEY set in  your environment",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "profile", Required: true},
	},
	Action: func(c *cli.Context) error {
		ctx := c.Context

		accessKeyFromEnv, accessKeyFromEnvExists := os.LookupEnv("AWS_ACCESS_KEY_ID")
		secretAccessKeyFromEnv, secretAccessKeyFromEnvExists := os.LookupEnv("AWS_SECRET_ACCESS_KEY")

		if accessKeyFromEnvExists && secretAccessKeyFromEnvExists {
			profileName := c.String("profile")
			profiles, err := cfaws.LoadProfiles()
			if err != nil {
				return err
			}

			if profiles.HasProfile(profileName) {
				return fmt.Errorf("profile with name '%s' already exist", profileName)
			}

			// create new static credential
			credentials, err := credentials.NewStaticCredentialsProvider(accessKeyFromEnv, secretAccessKeyFromEnv, "").Retrieve(ctx)
			if err != nil {
				return err
			}

			secureIAMCredentialStorage := securestorage.NewSecureIAMCredentialStorage()
			err = secureIAMCredentialStorage.StoreCredentials(profileName, credentials)
			if err != nil {
				return err
			}

			// fetch parsed credentials file
			credentialsFilePath := cfaws.GetAWSCredentialsPath()
			credentialsFile, err := ini.LoadSources(ini.LoadOptions{
				AllowNonUniqueSections:  false,
				SkipUnrecognizableLines: false,
				AllowNestedValues:       true,
			}, credentialsFilePath)
			if err != nil {
				return err
			}

			section, err := credentialsFile.NewSection(profileName)
			if err != nil {
				return err
			}
			err = section.ReflectFrom(&struct {
				AWSAccessKeyID     string `ini:"aws_access_key_id"`
				AWSSecretAccessKey string `ini:"aws_secret_access_key"`
			}{
				AWSAccessKeyID:     accessKeyFromEnv,
				AWSSecretAccessKey: secretAccessKeyFromEnv,
			})
			if err != nil {
				return err
			}
			err = credentialsFile.SaveTo(credentialsFilePath)
			if err != nil {
				return err
			}

			err = updateOrCreateProfileWithCredentialProcess(profileName)
			if err != nil {
				return err
			}

			clio.Successf("successfully created new profile %s", profileName)

			return nil

		}

		clio.Error("you don't have variables $AWS_ACCESS_KEY_ID and $AWS_SECRET_ACCESS_KEY set in your environment.")
		clio.Info("If you instead want to import plain-text credentials from ~/.aws/credentials to secure storage then run 'granted credentials import'")

		return nil

	},
}
