package request

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/common-fate/clio"
	"github.com/common-fate/grab"
	"github.com/fwdcloudsec/granted/pkg/accessrequest"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/fwdcloudsec/granted/pkg/cfcfg"
	"github.com/fwdcloudsec/granted/pkg/hook/accessrequesthook"
	"github.com/common-fate/sdk/eid"
	accessv1alpha1 "github.com/common-fate/sdk/gen/commonfate/access/v1alpha1"
	"github.com/common-fate/sdk/service/access/grants"
	identitysvc "github.com/common-fate/sdk/service/identity"
	"github.com/hako/durafmt"
	"github.com/urfave/cli/v2"
	"google.golang.org/protobuf/types/known/durationpb"
)

var Command = cli.Command{
	Name:  "request",
	Usage: "Request access to a role",
	Subcommands: []*cli.Command{
		&latestCommand,
		&checkCommand,
		&closeCommand,
	},
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

		// We first check if there was an active grant for this profile, and if there was, allow 30s of retries before bailing out
		cfg, cfConfigErr := cfcfg.Load(c.Context, profile)
		if err != nil {
			if cfConfigErr != nil {
				clio.Debugw("failed to load cfconfig, skipping check for active grants in a common fate deployment", "error", cfConfigErr)
			}
			return err
		}

		grantsClient := grants.NewFromConfig(cfg)
		idClient := identitysvc.NewFromConfig(cfg)
		callerID, err := idClient.GetCallerIdentity(c.Context, connect.NewRequest(&accessv1alpha1.GetCallerIdentityRequest{}))
		if err != nil {
			return fmt.Errorf("failed to load caller identity for user: %w", err)
		}
		grants, err := grab.AllPages(c.Context, func(ctx context.Context, nextToken *string) ([]*accessv1alpha1.Grant, *string, error) {
			grants, err := grantsClient.QueryGrants(c.Context, connect.NewRequest(&accessv1alpha1.QueryGrantsRequest{
				Principal: callerID.Msg.Principal.Eid,
				Target:    eid.New("AWS::Account", profile.AWSConfig.SSOAccountID).ToAPI(),
				// This API needs to be updated to use specifiers, for now, fetch all active grants and check for a match on the role name
				// Role:      eid.New("AWS::Account", profile.AWSConfig.SSOAccountID).ToAPI(),
				Status: accessv1alpha1.GrantStatus_GRANT_STATUS_ACTIVE.Enum(),
			}))
			if err != nil {
				return nil, nil, err
			}
			return grants.Msg.Grants, &grants.Msg.NextPageToken, nil
		})

		if err != nil {
			return fmt.Errorf("failed to query for active grants: %w", err)
		}

		for _, grant := range grants {
			if grant.Role.Name == profile.AWSConfig.SSORoleName {
				durationDescription := durafmt.Parse(time.Until(grant.ExpiresAt.AsTime())).LimitFirstN(1).String()
				clio.Infof("You already have an existing active grant for this profile which expires in %s, you can try assuming it now 'assume %s'", durationDescription, profile.Name)
				return nil
			}
		}

		hook := accessrequesthook.Hook{}
		reason := c.String("reason")
		duration := c.Duration("duration")
		var apiDuration *durationpb.Duration
		if duration != 0 {
			apiDuration = durationpb.New(duration)
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
