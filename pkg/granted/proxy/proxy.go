package proxy

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/session-manager-plugin/src/datachannel"
	"github.com/aws/session-manager-plugin/src/sessionmanagerplugin/session"
	"github.com/aws/session-manager-plugin/src/sessionmanagerplugin/session/portsession"
	"github.com/briandowns/spinner"
	"github.com/common-fate/clio"
	"github.com/common-fate/clio/clierr"
	"github.com/common-fate/grab"
	"github.com/fwdcloudsec/granted/internal/build"
	"github.com/fwdcloudsec/granted/pkg/cfaws"

	"github.com/common-fate/xid"
)

type DisplayOpts struct {
	//the e.g `aws rds proxy` which is used to fill in a help prompt
	Command string
	// like `EKS Proxy` or `RDS proxy`
	SessionType string
}
type AWSConfig struct {
	SSOAccountID     string
	SSORoleName      string
	SSORegion        string
	SSOStartURL      string
	Region           string
	SSMSessionTarget string
	NoCache          bool
}
type ConnectionOpts struct {
	ServerPort int
	LocalPort  int
}
type WaitForSSMConnectionToProxyServerOpts struct {
	AWSConfig      AWSConfig
	DisplayOpts    DisplayOpts
	ConnectionOpts ConnectionOpts
	GrantID        string
	RequestID      string
}

// WaitForSSMConnectionToProxyServer starts a session with SSM and waits for the connection to be ready
func WaitForSSMConnectionToProxyServer(ctx context.Context, opts WaitForSSMConnectionToProxyServerOpts) error {

	p := &cfaws.Profile{
		Name:        opts.GrantID,
		ProfileType: "AWS_SSO",
		AWSConfig: awsConfig.SharedConfig{
			SSOAccountID: opts.AWSConfig.SSOAccountID,
			SSORoleName:  opts.AWSConfig.SSORoleName,
			SSORegion:    opts.AWSConfig.SSORegion,
			SSOStartURL:  opts.AWSConfig.SSOStartURL,
		},
		Initialised: true,
	}

	creds, err := p.AssumeTerminal(ctx, cfaws.ConfigOpts{
		ShouldRetryAssuming: grab.Ptr(true),
		DisableCache:        opts.AWSConfig.NoCache,
	})
	if err != nil {
		return err
	}

	ssmReadyForConnectionsChan := make(chan struct{})

	awscfg, err := awsConfig.LoadDefaultConfig(ctx, awsConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)))
	if err != nil {
		return err
	}
	awscfg.Region = opts.AWSConfig.Region
	ssmClient := ssm.NewFromConfig(awscfg)

	var sessionOutput *ssm.StartSessionOutput

	documentName := "AWS-StartPortForwardingSession"
	startSessionInput := ssm.StartSessionInput{
		Target:       &opts.AWSConfig.SSMSessionTarget,
		DocumentName: &documentName,
		Parameters: map[string][]string{
			"portNumber":      {strconv.Itoa(opts.ConnectionOpts.ServerPort)},
			"localPortNumber": {strconv.Itoa(opts.ConnectionOpts.LocalPort)},
		},
		Reason: grab.Ptr(fmt.Sprintf("Session started for Granted %s connection with Common Fate. GrantID: %s, AccessRequestID: %s", opts.DisplayOpts.SessionType, opts.GrantID, opts.RequestID)),
	}

	sessionOutput, err = ssmClient.StartSession(ctx, &startSessionInput)
	if err != nil {
		return clierr.New("Failed to start AWS SSM port forward session",
			clierr.Error(err),
			clierr.Infof("You can try re-running this command with the verbose flag to see detailed logs, '%s --verbose %s'", build.GrantedBinaryName(), opts.DisplayOpts.Command),
			clierr.Infof("In rare cases, where the proxy service has been re-deployed while your grant was active, you will need to close your request in Common Fate and request access again 'cf access close request --id=%s' This is usually indicated by an error message containing '(TargetNotConnected) when calling the StartSession'", opts.RequestID))
	}

	clientId := xid.New("gtd")
	ssmSession := session.Session{
		StreamUrl:             *sessionOutput.StreamUrl,
		SessionId:             *sessionOutput.SessionId,
		TokenValue:            *sessionOutput.TokenValue,
		IsAwsCliUpgradeNeeded: false,
		Endpoint:              fmt.Sprintf("localhost:%d", opts.ConnectionOpts.LocalPort),
		DataChannel:           &datachannel.DataChannel{},
		ClientId:              clientId,
	}

	startingProxySpinner := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	startingProxySpinner.Suffix = fmt.Sprintf(" Starting %s...", opts.DisplayOpts.SessionType)
	startingProxySpinner.Writer = os.Stderr
	startingProxySpinner.Start()
	defer startingProxySpinner.Stop()

	// registers the PortSession feature within the ssm library
	_ = portsession.PortSession{}

	// the SSMDebugLogger serves two purposes here
	// 1. writes ssm session logs to clio.Debug which can be viewed using the --verbose flag
	// 2. scans the output for the string "Waiting for connections..." which indicates that the SSM connection was successful
	// The notifier will notify the ssmReadyForConnectionsChan which means we can connect to the proxy to complete the initial handshake
	ssmLogger := &SSMDebugLogger{
		Writers: []io.Writer{
			&NotifyOnSubstringMatchWriter{
				Phrase:   "Waiting for connections...",
				Callback: func() { ssmReadyForConnectionsChan <- struct{}{} },
			},
			DebugWriter{},
		},
	}

	// Connect to the Proxy server using SSM
	go func() {
		// Execute starts the ssm connection
		err = ssmSession.Execute(ssmLogger)
		if err != nil {
			clio.Error("AWS SSM port forward session closed with an error")
			clio.Error(err)
			clio.Info("You can try re-running this command with the verbose flag to see detailed logs, '%s --verbose %s'", build.GrantedBinaryName(), opts.DisplayOpts.Command)
			clio.Infof("In rare cases, where the proxy service has been re-deployed while your grant was active, you will need to close your request in Common Fate and request access again 'cf access close request --id=%s' This is usually indicated by an error message containing '(TargetNotConnected) when calling the StartSession'", opts.RequestID)
		}
	}()

	// waits for the ssm session to start or context to be cancelled
	select {
	case <-ssmReadyForConnectionsChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
