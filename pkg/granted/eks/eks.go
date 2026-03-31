package eks

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/common-fate/clio"
	"github.com/common-fate/grab"
	"github.com/fwdcloudsec/granted/pkg/cfcfg"
	"github.com/fwdcloudsec/granted/pkg/granted/proxy"
	"github.com/common-fate/sdk/config"
	accessv1alpha1 "github.com/common-fate/sdk/gen/commonfate/access/v1alpha1"
	"github.com/common-fate/sdk/service/access"

	"github.com/urfave/cli/v2"
)

var Command = cli.Command{
	Name:        "eks",
	Usage:       "Granted EKS plugin",
	Description: "Granted EKS plugin",
	Subcommands: []*cli.Command{&proxyCommand},
}

// isLocalMode is used where some behaviour needs to be changed to run against a local development proxy server
func isLocalMode(c *cli.Context) bool {
	return c.String("mode") == "local"
}

var proxyCommand = cli.Command{
	Name:  "proxy",
	Usage: "The Proxy plugin is used in conjunction with a Commnon Fate deployment to request temporary access to an AWS EKS Cluster",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "target", Aliases: []string{"cluster"}},
		&cli.StringFlag{Name: "role", Aliases: []string{"service-account"}},
		&cli.StringFlag{Name: "reason", Usage: "Provide a reason for requesting access to the role"},
		&cli.StringSliceFlag{Name: "attach", Usage: "Attach justifications to your request, such as a Jira ticket id or url `--attach=TP-123`"},
		&cli.BoolFlag{Name: "confirm", Aliases: []string{"y"}, Usage: "Skip confirmation prompts for access requests"},
		&cli.BoolFlag{Name: "wait", Value: true, Usage: "Wait for the access request to be approved."},
		&cli.BoolFlag{Name: "no-cache", Usage: "Disables caching of session credentials and forces a refresh", EnvVars: []string{"GRANTED_NO_CACHE"}},
		&cli.DurationFlag{Name: "duration", Aliases: []string{"d"}, Usage: "The duration for your access request"},
		&cli.StringFlag{Name: "mode", Hidden: true, Usage: "What mode to run the proxy command in, [remote,local], local is used in development to connect to a local instance of the proxy server rather than remote via SSM", Value: "remote"},
	},
	Action: func(c *cli.Context) error {
		ctx := c.Context
		cfg, err := config.LoadDefault(ctx)
		if err != nil {
			return err
		}

		err = cfg.Initialize(ctx, config.InitializeOpts{})
		if err != nil {
			return err
		}

		ensuredAccess, err := proxy.EnsureAccess(ctx, cfg, proxy.EnsureAccessInput[*accessv1alpha1.AWSEKSProxyOutput]{
			Target:               c.String("target"),
			Role:                 c.String("role"),
			Duration:             c.Duration("duration"),
			Reason:               c.String("reason"),
			Attachments:          c.StringSlice("attach"),
			Confirm:              c.Bool("confirm"),
			Wait:                 c.Bool("wait"),
			PromptForEntitlement: promptForClusterAndRole,
			GetGrantOutput: func(msg *accessv1alpha1.GetGrantOutputResponse) (*accessv1alpha1.AWSEKSProxyOutput, error) {
				output := msg.GetOutputAwsEksProxy()
				if output == nil {
					return nil, errors.New("unexpected grant output, this indicates an error in the Common Fate Provisioning process, you should contect your Common Fate administrator")
				}
				return output, nil
			},
		})
		if err != nil {
			return err
		}

		requestURL, err := cfcfg.GenerateRequestURL(cfg.APIURL, ensuredAccess.Grant.AccessRequestId)
		if err != nil {
			return err
		}

		serverPort, localPort, err := proxy.Ports(isLocalMode(c))
		if err != nil {
			return err
		}

		clio.Debugw("prepared ports for access", "serverPort", serverPort, "localPort", localPort)
		// In local mode ssm is not used, instead, the command connects directly to the proxy service running in local dev
		// Return early because there is nothing to startup
		if !isLocalMode(c) {
			err = proxy.WaitForSSMConnectionToProxyServer(ctx, proxy.WaitForSSMConnectionToProxyServerOpts{
				AWSConfig: proxy.AWSConfig{
					SSOAccountID:     ensuredAccess.GrantOutput.EksCluster.AccountId,
					SSORoleName:      ensuredAccess.GrantOutput.SsoRoleName,
					SSORegion:        ensuredAccess.GrantOutput.SsoRegion,
					SSOStartURL:      ensuredAccess.GrantOutput.SsoStartUrl,
					Region:           ensuredAccess.GrantOutput.EksCluster.Region,
					SSMSessionTarget: ensuredAccess.GrantOutput.SsmSessionTarget,
					NoCache:          c.Bool("no-cache"),
				},
				DisplayOpts: proxy.DisplayOpts{
					Command:     "aws eks proxy",
					SessionType: "EKS Proxy",
				},
				ConnectionOpts: proxy.ConnectionOpts{
					ServerPort: serverPort,
					LocalPort:  localPort,
				},
				GrantID:   ensuredAccess.Grant.Id,
				RequestID: ensuredAccess.Grant.AccessRequestId,
			})
			if err != nil {
				return err
			}
		}

		// Rather than the user having to specify a port via a flag, the proxy command just grabs an unused port to use.
		// it means that each time you run the
		tempPort, err := proxy.GrabUnusedPort()
		if err != nil {
			return err
		}

		underlyingProxyServerConn, yamuxStreamConnection, err := proxy.InitiateSessionConnection(cfg, proxy.InitiateSessionConnectionInput{
			GrantID:    ensuredAccess.Grant.Id,
			RequestURL: requestURL,
			LocalPort:  localPort,
		})
		if err != nil {
			return err
		}
		defer func() { _ = underlyingProxyServerConn.Close() }()
		defer func() { _ = yamuxStreamConnection.Close() }()

		err = AddContextToConfig(ensuredAccess, tempPort)
		if err != nil {
			return err
		}

		return proxy.ListenAndProxy(ctx, yamuxStreamConnection, tempPort, requestURL)
	},
}

// promptForClusterAndRole lists all available eks cluster entitlements for the user and displays a table selector UI
func promptForClusterAndRole(ctx context.Context, cfg *config.Context) (*accessv1alpha1.Entitlement, error) {
	accessClient := access.NewFromConfig(cfg)
	entitlements, err := grab.AllPages(ctx, func(ctx context.Context, nextToken *string) ([]*accessv1alpha1.Entitlement, *string, error) {
		res, err := accessClient.QueryEntitlements(ctx, connect.NewRequest(&accessv1alpha1.QueryEntitlementsRequest{
			PageToken:  grab.Value(nextToken),
			TargetType: grab.Ptr("AWS::EKS::Cluster"),
		}))
		if err != nil {
			return nil, nil, err
		}
		return res.Msg.Entitlements, &res.Msg.NextPageToken, nil
	})
	if err != nil {
		return nil, err
	}

	// check here to avoid nil pointer errors later
	if len(entitlements) == 0 {
		return nil, errors.New("you don't have access to any EKS Clusters")
	}

	return proxy.PromptEntitlements(entitlements, "Cluster", "Service Account", "Select a cluster to connect to: ")
}
