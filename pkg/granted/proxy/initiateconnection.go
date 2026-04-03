package proxy

import (
	"fmt"
	"net"

	"github.com/common-fate/clio"
	"github.com/common-fate/clio/clierr"
	"github.com/common-fate/sdk/config"
	"github.com/common-fate/sdk/handshake"
	"github.com/hashicorp/yamux"
)

type InitiateSessionConnectionInput struct {
	GrantID    string
	RequestURL string
	LocalPort  int
}

// InitiateSessionConnection starts a new tcp connection to through the SSM port forward and completes a handshake with the proxy server
// the result is a yamux session which is used to multiplex client connections
func InitiateSessionConnection(cfg *config.Context, input InitiateSessionConnectionInput) (net.Conn, *yamux.Session, error) {

	// First dial the local SSM portforward, which will be running on a randomly chosen port
	// or the local proxy server instance if it's local dev mode
	// this establishes the initial connection to the Proxy server
	clio.Debugw("dialing proxy server", "host", fmt.Sprintf("localhost:%d", input.LocalPort))
	rawServerConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", input.LocalPort))
	if err != nil {
		return nil, nil, clierr.New("failed to establish a connection to the remote proxy server", clierr.Error(err), clierr.Infof("Your grant may have expired, you can check the status here: %s and retry connecting", input.RequestURL))
	}
	// Next, a handshake is performed between the cli client and the Proxy server
	// this handshake establishes the users identity to the Proxy, and also the validity of a Database grant
	handshaker := handshake.NewHandshakeClient(rawServerConn, input.GrantID, cfg.TokenSource)
	handshakeResult, err := handshaker.Handshake()
	if err != nil {
		return nil, nil, clierr.New("failed to authenticate connection to the remote proxy server", clierr.Error(err), clierr.Infof("Your grant may have expired, you can check the status here: %s and retry connecting", input.RequestURL))
	}
	clio.Debugw("handshakeResult", "result", handshakeResult)

	// When the handshake process has completed successfully, we use yamux to establish a multiplexed stream over the existing connection
	// We use a multiplexed stream here so that multiple clients can be connected and have their logs attributed to the same session in our audit trail
	// To the clients, this is completely opaque
	multiplexedServerClient, err := yamux.Client(rawServerConn, nil)
	if err != nil {
		return nil, nil, err
	}

	// Sanity check to confirm that the multiplexed stream is working
	_, err = multiplexedServerClient.Ping()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to healthcheck the network connection to the proxy server: %w", err)
	}
	return rawServerConn, multiplexedServerClient, nil
}
