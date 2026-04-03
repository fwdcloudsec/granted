package request

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/cli/printdiags"
	"github.com/common-fate/clio"
	"github.com/common-fate/grab"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/fwdcloudsec/granted/pkg/cfcfg"
	"github.com/fwdcloudsec/granted/pkg/testable"
	"github.com/common-fate/sdk/config"
	"github.com/common-fate/sdk/eid"
	accessv1alpha1 "github.com/common-fate/sdk/gen/commonfate/access/v1alpha1"
	entityv1alpha1 "github.com/common-fate/sdk/gen/commonfate/entity/v1alpha1"
	"github.com/common-fate/sdk/service/access/grants"
	"github.com/common-fate/sdk/service/access/request"
	identitysvc "github.com/common-fate/sdk/service/identity"
	"github.com/urfave/cli/v2"
)

var closeCommand = cli.Command{
	Name:  "close",
	Usage: "Close an active Just-In-Time access to a particular entitlement",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "profile", Required: false, Usage: "Close a JIT access for a particular AWS profile"},
		&cli.StringFlag{Name: "request-id", Required: false, Usage: "Close a JIT access for a particular access request ID"},
	},
	Action: func(c *cli.Context) error {

		accessRequestID := c.String("request-id")
		profileName := c.String("profile")

		if accessRequestID != "" && profileName != "" {
			clio.Warn("Both profile and request-id were provided, profile will be ignored")
		}

		if accessRequestID != "" {
			ctx := c.Context

			cfg, err := config.LoadDefault(ctx)
			if err != nil {
				return err
			}

			client := request.NewFromConfig(cfg)

			closeRes, err := client.CloseAccessRequest(ctx, connect.NewRequest(&accessv1alpha1.CloseAccessRequestRequest{
				Id: accessRequestID,
			}))
			clio.Debugw("result", "closeAccessRequest", closeRes)
			if err != nil {
				return fmt.Errorf("failed to close access request: , %w", err)
			}

			haserrors := printdiags.Print(closeRes.Msg.Diagnostics, nil)
			if !haserrors {
				clio.Successf("access request %s is now closed", accessRequestID)
			}

			return nil
		}

		if profileName != "" {

			profiles, err := cfaws.LoadProfiles()
			if err != nil {
				return err
			}

			profile, err := profiles.LoadInitialisedProfile(c.Context, profileName)
			if err != nil {
				return err
			}

			cfg, err := cfcfg.Load(c.Context, profile)
			if err != nil {
				return fmt.Errorf("failed to load cfconfig, cannot check for active grants, %w", err)
			}

			grantsClient := grants.NewFromConfig(cfg)
			idClient := identitysvc.NewFromConfig(cfg)
			callerID, err := idClient.GetCallerIdentity(c.Context, connect.NewRequest(&accessv1alpha1.GetCallerIdentityRequest{}))
			if err != nil {
				return err
			}
			target := eid.New("AWS::Account", profile.AWSConfig.SSOAccountID)

			grants, err := grab.AllPages(c.Context, func(ctx context.Context, nextToken *string) ([]*accessv1alpha1.Grant, *string, error) {
				grants, err := grantsClient.QueryGrants(c.Context, connect.NewRequest(&accessv1alpha1.QueryGrantsRequest{
					Principal: callerID.Msg.Principal.Eid,
					Target:    target.ToAPI(),
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
				clearCacheProfileIfExists(profileName)
				return fmt.Errorf("failed to query for active grants: %w", err)
			}

			accessClient := request.NewFromConfig(cfg)

			for _, grant := range grants {
				if grant.Role.Name == profile.AWSConfig.SSORoleName {
					clio.Debugw("found active grant matching the profile, attempting to close grant", "grant", grant)

					res, err := accessClient.CloseAccessRequest(c.Context, connect.NewRequest(&accessv1alpha1.CloseAccessRequestRequest{
						Id: grant.AccessRequestId,
					}))
					clio.Debugw("result", "res", res)
					if err != nil {
						return err
					}
					clio.Successf("access to target %s and role %s is now closed", target, profile.AWSConfig.SSORoleName)
					return nil
				}
			}

			return fmt.Errorf("no active Access Request found for target %s and role %s", target, profile.AWSConfig.SSORoleName)
		}

		// Prompt the user with a list of active access requests if no flags are set
		ctx := c.Context
		cfg, err := config.LoadDefault(ctx)
		if err != nil {
			return err
		}
		accessClient := request.NewFromConfig(cfg)

		res, err := accessClient.QueryMyAccessRequests(ctx, connect.NewRequest(&accessv1alpha1.QueryMyAccessRequestsRequest{
			Order: entityv1alpha1.Order_ORDER_DESCENDING.Enum(),
		}))
		clio.Debugw("result", "res", res)
		if err != nil {
			return err
		}

		userAccessRequests := res.Msg.AccessRequests
		if len(res.Msg.AccessRequests) == 0 {
			clio.Error("There are no access requests that need to be closed")
			return nil
		}

		accessRequestsWithNames := []string{}
		for _, req := range userAccessRequests {
			// For now, add temporary code to check if the access request has granted that need to be closed
			// This part will be replaced by the implementation of the GrantStatus filter within QueryAccessRequests
			needsDeprovisioning := false
			for _, grant := range req.Grants {

				if grant.Status == accessv1alpha1.GrantStatus_GRANT_STATUS_ACTIVE && grant.ProvisioningStatus != accessv1alpha1.ProvisioningStatus(accessv1alpha1.ProvisioningStatus_PROVISIONING_STATUS_ATTEMPTING) {
					needsDeprovisioning = true
					break
				}
			}
			if needsDeprovisioning {
				accessRequestsWithNames = append(accessRequestsWithNames, req.Id)
			}
		}

		in := survey.Select{Message: "Please select the access request that you would like to close:", Options: accessRequestsWithNames}
		var out string
		err = testable.AskOne(&in, &out)
		if err != nil {
			return err
		}

		var selectedAccessRequest string

		for _, r := range userAccessRequests {
			if r.Id == out {
				selectedAccessRequest = r.Id
			}
		}

		closeRes, err := accessClient.CloseAccessRequest(ctx, connect.NewRequest(&accessv1alpha1.CloseAccessRequestRequest{
			Id: selectedAccessRequest,
		}))
		clio.Debugw("result", "closeAccessRequest", closeRes)
		if err != nil {
			return fmt.Errorf("failed to close access request: , %w", err)
		}

		haserrors := printdiags.Print(closeRes.Msg.Diagnostics, nil)
		if !haserrors {
			clio.Successf("access request %s is now closed", selectedAccessRequest)
		}

		return nil
	},
}
