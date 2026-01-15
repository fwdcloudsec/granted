package assume

import (
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/alessio/shellescape"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/common-fate/awsconfigfile"
	"github.com/common-fate/clio"
	"github.com/common-fate/clio/ansi"
	"github.com/common-fate/clio/clierr"
	"github.com/fwdcloudsec/granted/pkg/assumeprint"
	"github.com/fwdcloudsec/granted/pkg/browser"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/console"
	"github.com/fwdcloudsec/granted/pkg/forkprocess"
	"github.com/fwdcloudsec/granted/pkg/launcher"
	"github.com/fwdcloudsec/granted/pkg/testable"
	cfflags "github.com/fwdcloudsec/granted/pkg/urfav_overrides"
	"github.com/fatih/color"
	"github.com/hako/durafmt"
	"github.com/urfave/cli/v2"
	"gopkg.in/ini.v1"
)

// Launchers give a command that we need to run in order to launch a browser, such as
// 'open <URL>' or 'firefox --new-tab <URL'. The returned command is a string slice,
// with each element being an argument. (e.g. []string{"firefox", "--new-tab", "<URL>"})
type Launcher interface {
	LaunchCommand(url string, profile string) ([]string, error)
	// UseForkProcess returns true if the launcher implementation should call
	// the forkprocess library.
	//
	// For launchers that use 'open' commands, this should be false,
	// as the forkprocess library causes the following error to appear:
	// 	fork/exec open: no such file or directory
	UseForkProcess() bool
}
type execConfig struct {
	Cmd  string
	Args []string
}

// processArgsAndExecFlag will return the profileName if provided and the exec command config if the exec flag is used
// this supports both the -- variant and the legacy flag when passes the command and args as a string for backwards compatability
func processArgsAndExecFlag(c *cli.Context, assumeFlags *cfflags.Flags) (string, *execConfig, error) {
	execFlag := assumeFlags.String("exec")
	clio.Debugw("process args", "execFlag", execFlag, "osargs", os.Args, "c.args", c.Args().Slice())
	if execFlag == "" {
		return c.Args().First(), nil, nil
	}

	if execFlag == "--" {
		for i, arg := range os.Args {
			if arg == "--" {
				if len(os.Args) == i+1 {
					return "", nil, clierr.New("invalid arguments to exec call with '--'. Make sure you pass the command and argument after the doubledash.",
						clierr.Info("try running 'assume profilename --exec -- cmd arg1 arg2"))
				}
				cmdAndArgs := os.Args[i+1:]
				var args []string
				if len(cmdAndArgs) > 1 {
					args = cmdAndArgs[1:]
				}
				if c.Args().Len() > len(cmdAndArgs) {
					return c.Args().First(), &execConfig{cmdAndArgs[0], args}, nil
				} else {
					return "", &execConfig{cmdAndArgs[0], args}, nil
				}
			}
		}
	}

	parts := strings.SplitN(execFlag, " ", 2)
	var args []string
	if len(parts) > 1 {
		args = strings.Split(parts[1], " ")
	}
	return c.Args().First(), &execConfig{parts[0], args}, nil
}

func AssumeCommand(c *cli.Context) error {
	// assumeFlags allows flags to be passed on either side of the role argument.
	// to access flags in this command, use assumeFlags.String("region") etc instead of c.String("region")
	assumeFlags, err := cfflags.New("assumeFlags", GlobalFlags(), c)
	if err != nil {
		return err
	}

	if assumeFlags.String("exec") != "" && runtime.GOOS == "windows" {
		return clierr.New("--exec flag is not currently supported on Windows",
			clierr.Info("Let us know if you'd like support for this by creating an issue on our Github repo: https://github.com/fwdcloudsec/granted/issues/new"),
		)
	}

	profileName, execCfg, err := processArgsAndExecFlag(c, assumeFlags)
	if err != nil {
		return err
	}
	clio.Debug("processed profile name", profileName)
	clio.Debug("exec config:", execCfg)

	activeRoleProfile := assumeFlags.String("active-aws-profile")
	activeRoleFlag := assumeFlags.Bool("active-role")

	showRerunCommand := false
	var profile *cfaws.Profile
	if assumeFlags.Bool("sso") {
		profile, err = SSOProfileFromFlags(c)
		if err != nil {
			return err
		}

		// save the profile to the AWS config file if the user requested it.
		saveProfileName := assumeFlags.String("save-to")
		if saveProfileName != "" {
			configFilename := cfaws.GetAWSConfigPath()
			config, err := ini.LoadSources(ini.LoadOptions{
				AllowNonUniqueSections:  false,
				SkipUnrecognizableLines: false,
				AllowNestedValues:       true,
			}, configFilename)
			if err != nil {
				if !os.IsNotExist(err) {
					return err
				}
				config = ini.Empty()
			}
			err = awsconfigfile.Merge(awsconfigfile.MergeOpts{
				Config:              config,
				SectionNameTemplate: saveProfileName,
				Profiles: []awsconfigfile.SSOProfile{
					{
						SSOStartURL:   profile.SSOStartURL(),
						SSORegion:     profile.SSORegion(),
						AccountID:     profile.AWSConfig.SSOAccountID,
						AccountName:   profile.AWSConfig.SSOAccountID,
						RoleName:      profile.AWSConfig.SSORoleName,
						GeneratedFrom: "commonfate",
					},
				},
			})
			if err != nil {
				return err
			}

			err = config.SaveTo(configFilename)
			if err != nil {
				return err
			}

			clio.Successf("Saved AWS profile as %s. You can use this profile with the AWS CLI using the '--profile' flags when running AWS commands.", saveProfileName)
		}
	} else if activeRoleFlag && os.Getenv("GRANTED_SSO") == "true" {
		profile, err = SSOProfileFromEnv()
		if err != nil {
			return err
		}
	} else {
		var wg sync.WaitGroup

		profiles, err := cfaws.LoadProfiles()
		if err != nil {
			return err
		}

		if profileName != "" {
			if !profiles.HasProfile(profileName) {
				clio.Warnf("%s does not match any profiles in your AWS config or credentials files", profileName)
				profileName = ""
			}
		}

		//set the session creds using the active role if we have one and the flag is set
		if activeRoleFlag && activeRoleProfile != "" {
			if !profiles.HasProfile(activeRoleProfile) {
				clio.Warnf("You tried to use the -active-role flag but %s does not match any profiles in your AWS config or credentials files", activeRoleProfile)
			} else {
				profileName = activeRoleProfile
				clio.Infof("Using active profile: %s", profileName)
			}
		}
		if profileName != "" {
			// background task to update the frecency cache
			wg.Add(1)
			go func() {
				cfaws.UpdateFrecencyCache(profileName)
				wg.Done()
			}()
		}

		// if profile is still "" here, then prompt to select a profile
		if profileName == "" {
			showRerunCommand = true

			profileName, err = QueryProfiles(profiles)
			if err != nil {
				return err
			}
			// background task to update the frecency cache
			wg.Add(1)
			go func() {
				cfaws.UpdateFrecencyCache(profileName)
				wg.Done()
			}()
		}

		// finally, load the profile and initialise it, this builds the parent tree structure
		profile, err = profiles.LoadInitialisedProfile(c.Context, profileName)
		if err != nil {
			return err
		}
	}

	// inline role Chaining works by creating a mock config section/profile configured with the parent as it's source
	// this means that existing assumers can be used to handle the base profile credential sourcing and assuming
	if assumeFlags.String("chain") != "" {
		// create a new aws shared config profile by copying most of the default config from the source profile
		chainProfile := awsconfig.SharedConfig{
			Source:                           &profile.AWSConfig,
			SourceProfileName:                profile.Name,
			RoleARN:                          assumeFlags.String("chain"),
			Profile:                          assumeFlags.String("chain"),
			EnableEndpointDiscovery:          profile.AWSConfig.EnableEndpointDiscovery,
			S3UseARNRegion:                   profile.AWSConfig.S3UseARNRegion,
			EC2IMDSEndpointMode:              profile.AWSConfig.EC2IMDSEndpointMode,
			EC2IMDSEndpoint:                  profile.AWSConfig.EC2IMDSEndpoint,
			S3DisableMultiRegionAccessPoints: profile.AWSConfig.S3DisableMultiRegionAccessPoints,
			UseDualStackEndpoint:             profile.AWSConfig.UseDualStackEndpoint,
			UseFIPSEndpoint:                  profile.AWSConfig.UseFIPSEndpoint,
			DefaultsMode:                     profile.AWSConfig.DefaultsMode,
			RetryMaxAttempts:                 profile.AWSConfig.RetryMaxAttempts,
			RetryMode:                        profile.AWSConfig.RetryMode,
			CustomCABundle:                   profile.AWSConfig.CustomCABundle,
		}
		emptySection, err := ini.Empty().NewSection("empty")
		if err != nil {
			return err
		}

		profile = &cfaws.Profile{
			// empty section as a placeholder
			RawConfig:   emptySection,
			Name:        assumeFlags.String("chain"),
			File:        profile.File,
			ProfileType: profile.ProfileType,
			Parents:     append(profile.Parents, profile),
			AWSConfig:   chainProfile,
			Initialised: true,
		}
	}

	var region string
	// The region flag may be supplied in shorthand form, first check if the flag is set and expand the region
	// else use the profile region
	if assumeFlags.String("region") != "" {
		regionFlag := assumeFlags.String("region")
		region, err = cfaws.ExpandRegion(regionFlag)
		if err != nil {
			return fmt.Errorf("couldn't parse region %s: %v", region, err)
		}
	} else {
		region, err = profile.Region(c.Context)
		if err != nil {
			return err
		}
	}

	configOpts := cfaws.ConfigOpts{
		Duration:          time.Hour,
		MFATokenCode:      assumeFlags.String("mfa-token"),
		Args:              assumeFlags.StringSlice("pass-through"),
		DisableCache:      assumeFlags.Bool("no-cache"),
		SSOBrowserProfile: assumeFlags.String("sso-browser-profile"),
	}

	// attempt to get session duration from profile
	if profile.AWSConfig.RoleDurationSeconds != nil {
		configOpts.Duration = *profile.AWSConfig.RoleDurationSeconds
	}

	duration := assumeFlags.String("duration")
	if duration != "" {
		d, err := time.ParseDuration(duration)
		if err != nil {
			return err
		}
		configOpts.Duration = d
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// if getConsoleURL is true, we'll use the AWS federated login to retrieve a URL to access the console.
	// depending on how Granted is configured, this is then printed to the terminal or a browser is launched at the URL automatically.
	getConsoleURL := !assumeFlags.Bool("env") && ((assumeFlags.Bool("console") || assumeFlags.String("console-destination") != "") || assumeFlags.Bool("active-role") || assumeFlags.String("service") != "" || assumeFlags.Bool("url"))

	// this makes it easy for users to copy the actual command and avoid needing to lookup profiles
	if !cfg.DisableUsageTips && showRerunCommand {
		clio.Infof("To assume this profile again later without needing to select it, run this command:\n> assume %s %s", profile.Name, strings.Join(os.Args[1:], " "))
	}

	if getConsoleURL {
		con := console.AWS{
			Profile:     profile.Name,
			Service:     assumeFlags.String("service"),
			Region:      region,
			Destination: assumeFlags.String("console-destination"),
		}

		creds, err := profile.AssumeConsole(c.Context, configOpts)
		if err != nil && strings.HasPrefix(err.Error(), "no access") {
			clio.Debugw("received a No Access error", "error", err)
			// TODO: this is where we can add a hook in future to allow users to define a shell script to be executed to automatically request access, etc.
		}

		if err != nil {
			return err
		}

		containerProfile := profile.Name

		if assumeFlags.String("browser-profile") != "" {
			containerProfile = assumeFlags.String("browser-profile")
		}

		consoleURL, err := con.URL(creds)
		if err != nil {
			return err
		}

		if cfg.DefaultBrowser == browser.FirefoxKey || cfg.DefaultBrowser == browser.WaterfoxKey || cfg.DefaultBrowser == browser.FirefoxStdoutKey || cfg.DefaultBrowser == browser.FirefoxDevEditionKey || cfg.DefaultBrowser == browser.FirefoxNightlyKey {
			// transform the URL into the Firefox Tab Container format.
			consoleURL = fmt.Sprintf("ext+granted-containers:name=%s&url=%s&color=%s&icon=%s", containerProfile, url.QueryEscape(consoleURL), profile.CustomGrantedProperty("color"), profile.CustomGrantedProperty("icon"))
		}

		justPrintURL := assumeFlags.Bool("url") || cfg.DefaultBrowser == browser.StdoutKey || cfg.DefaultBrowser == browser.FirefoxStdoutKey
		if justPrintURL {
			// return the url via stdout through the CLI wrapper script and return early.
			fmt.Print(assumeprint.SafeOutput(consoleURL))
			return nil
		}

		browserPath := cfg.CustomBrowserPath
		if browserPath == "" && cfg.AWSConsoleBrowserLaunchTemplate == nil {
			return errors.New("default browser not configured. run `granted browser set` to configure")
		}

		var l Launcher
		switch cfg.DefaultBrowser {
		case browser.ChromeKey, browser.BraveKey, browser.EdgeKey, browser.ChromiumKey, browser.VivaldiKey:
			l = launcher.ChromeProfile{
				BrowserType:    cfg.DefaultBrowser,
				ExecutablePath: browserPath,
			}
		case browser.FirefoxKey, browser.WaterfoxKey:
			l = launcher.Firefox{
				ExecutablePath: browserPath,
			}
		case browser.SafariKey:
			l = launcher.Safari{}
		case browser.ArcKey:
			l = launcher.Arc{}
		case browser.FirefoxDevEditionKey:
			l = launcher.FirefoxDevEdition{
				ExecutablePath: browserPath,
			}
		case browser.FirefoxNightlyKey:
			l = launcher.FirefoxNightly{
				ExecutablePath: browserPath,
			}
		case browser.CustomKey:
			l, err = launcher.CustomFromLaunchTemplate(cfg.AWSConsoleBrowserLaunchTemplate, c.StringSlice("browser-launch-template-arg"))
			if err == launcher.ErrLaunchTemplateNotConfigured {
				return errors.New("error configuring custom browser, ensure that [AWSConsoleBrowserLaunchTemplate] is specified in your Granted config file")
			}
			if err != nil {
				return err
			}
		default:
			l = launcher.Open{}
		}

		printFlagUsage(con.Region, con.Service)
		clio.Infof("Opening a console for %s in your browser...", profile.Name)

		// now build the actual command to run - e.g. 'firefox --new-tab <URL>'
		args, err := l.LaunchCommand(consoleURL, containerProfile)
		if err != nil {
			return fmt.Errorf("error building browser launch command: %w", err)
		}

		var startErr error
		if l.UseForkProcess() {
			clio.Debugf("running command using forkprocess: %s", args)
			cmd, err := forkprocess.New(args...)
			if err != nil {
				return err
			}
			startErr = cmd.Start()
		} else {
			clio.Debugf("running command without forkprocess: %s", args)
			cmd := exec.Command(args[0], args[1:]...)
			startErr = cmd.Start()
		}

		if startErr != nil {
			return clierr.New(fmt.Sprintf("Granted was unable to open a browser session automatically due to the following error: %s", startErr.Error()),
				// allow them to try open the url manually
				clierr.Info("You can open the browser session manually using the following url:"),
				clierr.Info(consoleURL),
			)
		}
	}

	// check if it's needed to provide credentials to terminal or default to it if console wasn't specified
	if assumeFlags.Bool("terminal") || !getConsoleURL {
		creds, err := profile.AssumeTerminal(c.Context, configOpts)
		if err != nil && strings.HasPrefix(err.Error(), "no access") {
			clio.Debugw("received a No Access error", "error", err)
			// TODO: this is where we can add a hook in future to allow users to define a shell script to be executed to automatically request access, etc.
		}

		if err != nil {
			return err
		}
		sessionExpiration := ""
		if creds.CanExpire {
			sessionExpiration = creds.Expires.Local().Format(time.RFC3339)
			// We add 10 seconds here as a fudge factor, the credentials will be a
			// few seconds old already.
			durationDescription := durafmt.Parse(time.Until(creds.Expires) + 10*time.Second).LimitFirstN(1).String()
			if os.Getenv("GRANTED_QUIET") != "true" {
				clio.Successf("[%s](%s) session credentials will expire in %s", profile.Name, region, durationDescription)
			}
		} else if os.Getenv("GRANTED_QUIET") != "true" {
			clio.Successf("[%s](%s) session credentials ready", profile.Name, region)
		}
		if assumeFlags.Bool("env") {
			err = cfaws.WriteCredentialsToDotenv(region, creds)
			if err != nil {
				return err
			}
			clio.Success("Exported credentials to .env file successfully")
		}

		if assumeFlags.Bool("export") || cfg.ExportCredsToAWS {
			err = cfaws.ExportCredsToProfile(profile.Name, creds)
			if err != nil {
				return err
			}
			var profileName string
			if cfg.ExportCredentialSuffix != "" {
				profileName = profile.Name + "-" + cfg.ExportCredentialSuffix

			} else {
				profileName = profile.Name
				clio.Warn("No credential suffix found. This can cause issues with using exported credentials if conflicting profiles exist. Run `granted settings export-suffix set` to set one.")
			}

			credentialsFilePath := cfaws.GetAWSCredentialsPath()
			clio.Successf("Exported credentials to %s file as %s successfully", credentialsFilePath, profileName)
		}

		if assumeFlags.Bool("export-sso-token") || cfg.ExportSSOToken {
			err := cfaws.ExportAccessTokenToCache(c.Context, profile)

			if err != nil {
				return err
			}

			clio.Success("Exported sso token to ~/.aws/sso/cache")
		}

		if execCfg != nil {
			escapedCmd := shellescape.QuoteCommand(append([]string{execCfg.Cmd}, execCfg.Args...))
			output := PrepareStringsForShellScript([]string{creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, "", region, "", "false", "", "", "", "", escapedCmd})
			fmt.Printf("GrantedExec %s %s %s %s %s %s %s %s %s %s %s %s", output...)
			return nil
		}

		if profile.RawConfig != nil && profile.RawConfig.HasKey("credential_process") && (assumeFlags.Bool("export-all-env-vars") || cfg.DefaultExportAllEnvVar) {
			output := PrepareStringsForShellScript([]string{creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, profile.Name, region, sessionExpiration, "true", profile.SSOStartURL(), profile.AWSConfig.SSORoleName, profile.SSORegion(), profile.AWSConfig.SSOAccountID, ""})
			fmt.Printf("GrantedAssume %s %s %s %s %s %s %s %s %s %s %s %s", output...)
			return nil
		}

		// DO NOT REMOVE, this interacts with the shell script that wraps the assume command, the shell script is what configures your shell environment vars
		// to export more environment variables, add then in the assume and assume.fish scripts then append them to this output preparation function
		// the shell script treats "None" as an empty string and will not set a value for that positional output

		// If the profile uses "credential_process" to source credential externally then do not set accessKeyId, secretAccessKey, sessionToken
		// so that aws cli automatically refreshes credential when they expire.
		if profile.RawConfig != nil && profile.RawConfig.HasKey("credential_process") {
			output := PrepareStringsForShellScript([]string{"", "", "", profile.Name, region, "", "", "", "", "", "", ""})
			fmt.Printf("GrantedAssume %s %s %s %s %s %s %s %s %s %s %s %s", output...)

			return nil
		}

		if assumeFlags.Bool("sso") {
			output := PrepareStringsForShellScript([]string{creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, "", region, sessionExpiration, "true", profile.SSOStartURL(), profile.AWSConfig.SSORoleName, profile.SSORegion(), profile.AWSConfig.SSOAccountID, ""})
			fmt.Printf("GrantedAssume %s %s %s %s %s %s %s %s %s %s %s %s", output...)

			return nil
		}

		//  When using the `--chain` flag, the profile does not exist because it is an ARN we are assuming, not a profile generated by granted.
		//  Since the profile does not exist, the awscli will error due to it attempting to use a non-existent profile.
		if assumeFlags.String("chain") != "" {
			profile.Name = "None"
		}

		output := PrepareStringsForShellScript([]string{creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, profile.Name, region, sessionExpiration, "false", "", "", "", "", ""})
		fmt.Printf("GrantedAssume %s %s %s %s %s %s %s %s %s %s %s %s", output...)
	}
	return nil
}

// PrepareCredentialsForShellScript will set empty values to "None", this is required by the shell script to identify which variables to unset
// it is also required to ensure that the return values are correctly split, e.g if sessionToken is "" then profile name will be used to set the session token environment variable
func PrepareStringsForShellScript(in []string) []interface{} {
	out := []interface{}{}
	for _, s := range in {
		if s == "" {
			out = append(out, "None")
		} else {
			out = append(out, s)
		}

	}
	return out
}

// RunExecCommandWithCreds takes in a command, which may be a program and arguments separated by spaces
// it splits these then runs the command with the credentials as the environment.
// The output of this is returned via the assume script to stdout so it may be processed further by piping
func RunExecCommandWithCreds(creds aws.Credentials, region string, cmd string, args ...string) error {
	fmt.Print(assumeprint.SafeOutput(""))
	c := exec.Command(cmd, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	// the aws profile env var will break the exec flow so we strip it out
	c.Env = append(removeEnvKeys(os.Environ(), []string{"AWS_PROFILE"}), EnvKeys(creds, region)...)
	return c.Run()
}
func removeEnvKeys(env []string, keysToRemove []string) []string {
	remainingEnv := []string{}

	// Create a map of keys to remove for faster lookup
	keysToRemoveMap := make(map[string]struct{})
	for _, key := range keysToRemove {
		keysToRemoveMap[key] = struct{}{}
	}

	for _, e := range env {
		pair := strings.SplitN(e, "=", 2)
		if len(pair) != 2 {
			// Malformed environment variable; skip it
			continue
		}

		key := pair[0]
		if _, shouldRemove := keysToRemoveMap[key]; !shouldRemove {
			remainingEnv = append(remainingEnv, e)
		}
	}

	return remainingEnv
}

// EnvKeys is used to set the env for the "exec" flag
func EnvKeys(creds aws.Credentials, region string) []string {
	return []string{"AWS_ACCESS_KEY_ID=" + creds.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + creds.SecretAccessKey,
		"AWS_SESSION_TOKEN=" + creds.SessionToken,
		"AWS_REGION=" + region}
}

func filterMultiToken(filterValue string, optValue string, optIndex int) bool {
	optValue = strings.ToLower(optValue)
	filters := strings.Split(strings.ToLower(filterValue), " ")
	for _, filter := range filters {
		if !strings.Contains(optValue, filter) {
			return false
		}
	}
	return true
}

func printFlagUsage(region, service string) {
	var m []string
	if region == "" {
		m = append(m, "use -r to open a specific region")
	}
	if service == "" {
		m = append(m, "use -s to open a specific service")
	}
	if region == "" || service == "" {
		clio.Infof("%s ( https://docs.commonfate.io/granted/usage/console )", strings.Join(m, " or "))
	}
}

func QueryProfiles(profiles *cfaws.Profiles) (string, error) {
	withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
	// load config to check frecency enabled
	cfg, err := config.Load()
	if err != nil {
		return "", err
	}

	_, profileNames := profiles.GetFrecentProfiles()
	if cfg.Ordering == "Alphabetical" {
		profileNames = profiles.ProfileNames
	}
	profileNameMap := make(map[string]string)
	profileKeys := make([]string, len(profileNames))
	var longestProfileNameLength int
	for _, pn := range profileNames {
		if len(pn) > longestProfileNameLength {
			longestProfileNameLength = len(pn)
		}
	}
	lightBlack := ansi.ColorFunc(ansi.LightBlack)
	var hasDescriptions bool
	for i, pn := range profileNames {
		var description string
		p, _ := profiles.Profile(pn)

		if p != nil && p.CustomGrantedProperty("description") != "" {
			hasDescriptions = true
			description = p.CustomGrantedProperty("description")
		}

		stringKey := fmt.Sprintf("%-"+strconv.Itoa(longestProfileNameLength)+"s%s", pn, lightBlack(description))

		profileNameMap[stringKey] = pn
		profileKeys[i] = stringKey
	}
	var promptHeader string
	// only add the description headers if there are profiles using descriptions
	if hasDescriptions {
		promptHeader = fmt.Sprintf(`{{- "  %s\n"}}`, color.New(color.Underline, color.Bold).Sprintf("%-"+strconv.Itoa(longestProfileNameLength)+"s%s", "Profile", "Description"))
	}
	// This overrides the default prompt template to add a header row above the options
	// this should be reset back to the original template after the call to AskOne
	originalSelectTemplate := survey.SelectQuestionTemplate
	survey.SelectQuestionTemplate = fmt.Sprintf(`
{{- define "option"}}
    {{- if eq .SelectedIndex .CurrentIndex }}{{color .Config.Icons.SelectFocus.Format }}{{ .Config.Icons.SelectFocus.Text }} {{else}}{{color "default"}}  {{end}}
    {{- .CurrentOpt.Value}}{{ if ne ($.GetDescription .CurrentOpt) "" }} - {{color "cyan"}}{{ $.GetDescription .CurrentOpt }}{{end}}
    {{- color "reset"}}
{{end}}
{{- if .ShowHelp }}{{- color .Config.Icons.Help.Format }}{{ .Config.Icons.Help.Text }} {{ .Help }}{{color "reset"}}{{"\n"}}{{end}}
{{- color .Config.Icons.Question.Format }}{{ .Config.Icons.Question.Text }} {{color "reset"}}
{{- color "default+hb"}}{{ .Message }}{{ .FilterMessage }}{{color "reset"}}
{{- if .ShowAnswer}}{{color "cyan"}} {{.Answer}}{{color "reset"}}{{"\n"}}
{{- else}}
  {{- "  "}}{{- color "cyan"}}[Use arrows to move, type to filter{{- if and .Help (not .ShowHelp)}}, {{ .Config.HelpInput }} for more help{{end}}]{{color "reset"}}
  {{- "\n"}}
%s{{- "\n"}}
  {{- range $ix, $option := .PageEntries}}
    {{- template "option" $.IterateOption $ix $option}}
  {{- end}}
{{- end}}`, promptHeader)

	clio.NewLine()
	// Replicate the logic from original assume fn.
	in := survey.Select{
		Message: "Please select the profile you would like to assume:",
		Options: profileKeys,
		Filter:  filterMultiToken,
	}
	if len(profileKeys) == 0 {
		return "", clierr.New("Granted couldn't find any AWS profiles in your config file or your credentials file",
			clierr.Info("You can add profiles to your AWS config by following our guide: "),
			clierr.Info("https://docs.commonfate.io/granted/getting-started#set-up-your-aws-profile-file"),
		)
	}

	var profileName string

	err = testable.AskOne(&in, &profileName, withStdio)
	if err != nil {
		return "", err
	}
	// Reset the template for select questions to the original
	survey.SelectQuestionTemplate = originalSelectTemplate
	profileName = profileNameMap[profileName]
	// background task to update the frecency cache

	return profileName, nil
}
