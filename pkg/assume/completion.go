package assume

import (
	"fmt"
	"os"
	"strings"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/fwdcloudsec/granted/pkg/console"
	"github.com/urfave/cli/v2"
)

// If there are more than 2 args and the last argument is a "-" then provide completion for the flags.
//
// Else, provide completion for the aws profiles.
//
// You can use `assume -c ` + tab to get profile names or `assume -` + tab to get flags
func Completion(ctx *cli.Context) {
	var awsRegions = []string{
		"us-east-1",      // US East (N. Virginia)
		"us-east-2",      // US East (Ohio)
		"us-west-1",      // US West (N. California)
		"us-west-2",      // US West (Oregon)
		"af-south-1",     // Africa (Cape Town)
		"ap-east-1",      // Asia Pacific (Hong Kong)
		"ap-south-1",     // Asia Pacific (Mumbai)
		"ap-northeast-1", // Asia Pacific (Tokyo)
		"ap-northeast-2", // Asia Pacific (Seoul)
		"ap-northeast-3", // Asia Pacific (Osaka)
		"ap-southeast-1", // Asia Pacific (Singapore)
		"ap-southeast-2", // Asia Pacific (Sydney)
		"ca-central-1",   // Canada (Central)
		"eu-central-1",   // EU (Frankfurt)
		"eu-west-1",      // EU (Ireland)
		"eu-west-2",      // EU (London)
		"eu-west-3",      // EU (Paris)
		"eu-north-1",     // EU (Stockholm)
		"eu-south-1",     // EU (Milan)
		"me-south-1",     // Middle East (Bahrain)
		"sa-east-1",      // South America (Sao Paulo)
	}

	clio.SetLevelFromEnv("GRANTED_LOG")
	if ctx.Bool("verbose") {
		clio.SetLevelFromString("debug")
	}

	// autocompletion for service flag
	if len(os.Args) > 2 {

		// reduce -- to - to make matching simpler
		arg := os.Args[len(os.Args)-2]
		if strings.HasPrefix(arg, "--") {
			arg = arg[1:]
		}
		if arg == "-s" || arg == "-service" {
			for k := range console.ServiceMap {
				fmt.Println(k)
			}
			return
		}
		if arg == "-r" || arg == "-region" {
			fmt.Println(strings.Join(awsRegions, "\n"))
			return
		}

		if strings.HasPrefix(arg, "-") {
			ctx.App.Writer = os.Stdout
			cli.DefaultAppComplete(ctx)
		}
	}

	awsProfiles, _ := cfaws.LoadProfiles()

	// profileName argument can have any position to the command
	// this check will help in not showing the profile name again it's already included.
	hasProfileNameArg := false
	for _, arg := range os.Args {
		for _, awsProfile := range awsProfiles.ProfileNames {
			if arg == awsProfile {
				hasProfileNameArg = true
			}
		}
	}

	if !hasProfileNameArg {
		// Tab completion script requires each option to be separated by a newline
		fmt.Println(strings.Join(awsProfiles.ProfileNames, "\n"))
	}
}
