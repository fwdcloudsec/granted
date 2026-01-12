package registry

import (
	"os"
	"path"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	"github.com/common-fate/clio/clierr"
	"github.com/fwdcloudsec/granted/pkg/git"

	"github.com/urfave/cli/v2"
)

var SetupCommand = cli.Command{
	Name:        "setup",
	Usage:       "Setup a Profile Registry repository",
	Description: "Setup a granted registry repository",
	Subcommands: []*cli.Command{},
	Flags:       []cli.Flag{&cli.PathFlag{Name: "dir", Aliases: []string{"d"}, Usage: "Directory to setup the Profile Registry", Value: "granted-registry"}},
	Action: func(c *cli.Context) error {
		dir := c.Path("dir")

		// check that it is an empty dir
		err := ensureConfigDoesntExist(dir)
		if err != nil {
			return err
		}

		// mkdir granted-registry
		err = os.Mkdir(dir, 0755)
		if err != nil {
			return err
		}

		// copy ~/.aws/config to ./config
		configFile, _, err := loadAWSConfigFile()
		if err != nil {
			return err
		}

		var confirm bool
		s := &survey.Confirm{
			Message: "Are you sure you want to copy all of the profiles from your AWS config file?",
			Default: true,
		}
		err = survey.AskOne(s, &confirm)
		if err != nil {
			return err
		}
		if !confirm {
			clio.Info("Cancelled registry setup")
			return nil
		}

		// now save cfg contents to ./config

		err = configFile.SaveTo(path.Join(dir, "config"))
		if err != nil {
			return err
		}

		// create granted.yml

		f, err := os.Create(path.Join(dir, "granted.yml"))
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		// now initialize the git repo
		err = git.Init(dir)
		if err != nil {
			return err
		}
		// write the default config to the granted.yml
		_, err = f.WriteString(`awsConfig:
    - ./config`)
		if err != nil {
			return err
		}
		clio.Infof("Successfully created valid profile registry 'granted-registry' in %s.", dir)
		clio.Info("Now push this repository to remote origin so that your team-members can sync to it.")
		return nil
	},
}

// sanity check: verify that a config file doesn't already exist.
// if it does, the user may have run this command by mistake.
func ensureConfigDoesntExist(dir string) error {
	_, err := os.Open(path.Join(dir, "granted.yml"))
	if err != nil {
		return nil
	}

	// if we get here, the config file exists and is at risk of being overwritten.
	return clierr.New(("A granted.yml file already exists in this folder.\ngranted will exit to avoid overwriting this file, in case you've run this command by mistake."),
		clierr.Info(`Alternatively, take one of the following actions:
  a) run 'granted registry setup' in a different directory
  b) run 'granted registry add' to connect to an existing Profile Registry
`))
}
