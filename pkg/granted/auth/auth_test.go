package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func runCommand(cmd cli.Command, args ...string) error {
	app := &cli.App{Commands: []*cli.Command{&cmd}}
	return app.Run(append([]string{"granted", cmd.Name}, args...))
}

func TestLoginCommand_MissingURL(t *testing.T) {
	err := runCommand(loginCommand)
	assert.ErrorContains(t, err, "please provide a provider URL")
}

func TestLoginCommand_UnsupportedAuthType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"provider":"example","auth":{"type":"saml"}}`))
	}))
	defer srv.Close()

	err := runCommand(loginCommand, "--url", srv.URL)
	assert.ErrorContains(t, err, "unsupported auth type")
	assert.ErrorContains(t, err, "saml")
}

func TestLoginCommand_ProviderURLFromPositionalArg(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"provider":"example","auth":{"type":"saml"}}`))
	}))
	defer srv.Close()

	// no --url flag, just a positional argument
	err := runCommand(loginCommand, srv.URL)
	assert.ErrorContains(t, err, "unsupported auth type")
}

func TestLoginCommand_ProviderConfigLoadFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := runCommand(loginCommand, "--url", srv.URL)
	assert.ErrorContains(t, err, "failed to load provider config")
}

func TestLogoutCommand_MissingURL(t *testing.T) {
	err := runCommand(logoutCommand)
	assert.ErrorContains(t, err, "please provide a provider URL")
}
