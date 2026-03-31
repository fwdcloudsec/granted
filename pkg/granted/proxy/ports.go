package proxy

import (
	"net"
)

// Returns the proxy port to connect to and a local port to send client connections to
// in production, an SSM portforward process is running which is used to connect to the proxy server
// and over the top of this connection, a handshake process takes place and connection multiplexing is used to handle multiple database clients
func Ports(isLocalMode bool) (serverPort, localPort int, err error) {
	// in local mode the SSM port forward is not used can skip using ssm and just use a local port forward instead
	if isLocalMode {
		return 7070, 7070, nil
	}
	// find an unused local port to use for the ssm server
	// the user doesn't directly connect to this, they connect through our local proxy
	// which adds authentication
	ssmPortforwardLocalPort, err := GrabUnusedPort()
	if err != nil {
		return 0, 0, err
	}
	return 8080, ssmPortforwardLocalPort, nil
}

func GrabUnusedPort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}

	port := listener.Addr().(*net.TCPAddr).Port
	err = listener.Close()
	if err != nil {
		return 0, err
	}
	return port, nil
}
