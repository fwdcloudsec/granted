package request

import (
	"context"
	"time"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/accessrequest"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/fwdcloudsec/granted/pkg/hook/accessrequesthook"
	"github.com/fwdcloudsec/granted/pkg/hook/httpprovider"
	"github.com/fwdcloudsec/granted/pkg/providercfg"
	"github.com/urfave/cli/v2"
)

var Command = cli.Command{
	Name:  "request",
	Usage: "Request access to a role",
	Subcommands: []*cli.Command{
		&latestCommand,
		// TODO: re-enable check and close commands with HTTP provider
	},
}

func newHTTPProvider(providerURL string) (accessrequesthook.AccessProvider, error) {
	cfg, err := providercfg.LoadFromURL(context.Background(), providerURL)
	if err != nil {
		return nil, err
	}
	return httpprovider.New(cfg, providerURL, ""), nil
}

var latestCommand = cli.Command{
	Name:  "latest",
	Usage: "Request access to the latest AWS role you attempted to use",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "reason", Usage: "A reason for access"},
		&cli.StringSliceFlag{Name: "attach", Usage: "Attach justifications to your request, such as a Jira ticket id or url `--attach=TP-123`"},
		&cli.DurationFlag{Name: "duration", Usage: "Duration of request, defaults to max duration of the access rule."},
		&cli.BoolFlag{Name: "confirm", Aliases: []string{"y"}, Usage: "Skip confirmation prompts for access requests"},
	},
	Action: func(c *cli.Context) error {
		latest, err := accessrequest.LatestProfile()
		if err != nil {
			return err
		}

		profiles, err := cfaws.LoadProfiles()
		if err != nil {
			return err
		}

		profile, err := profiles.LoadInitialisedProfile(c.Context, latest.Name)
		if err != nil {
			return err
		}

		hook, err := accessrequesthook.NewHookFromProfile(profile, newHTTPProvider)
		if err != nil {
			clio.Debugw("failed to create access hook", "error", err)
			return err
		}
		if hook == nil {
			clio.Info("No access provider configured for this profile")
			return nil
		}

		reason := c.String("reason")
		duration := c.Duration("duration")
		var apiDuration *time.Duration
		if duration != 0 {
			apiDuration = &duration
		}

		_, _, err = hook.NoAccess(c.Context, accessrequesthook.NoAccessInput{
			Profile:     profile,
			Reason:      reason,
			Attachments: c.StringSlice("attach"),
			Duration:    apiDuration,
			Confirm:     c.Bool("confirm"),
		})
		if err != nil {
			return err
		}

		return nil
	},
}
