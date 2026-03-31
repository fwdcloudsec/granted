// Package exp holds experimental commands.
// The API and arguments of these these commands are subject to change.
package exp

import (
	"github.com/fwdcloudsec/granted/pkg/granted/exp/request"
	"github.com/urfave/cli/v2"
)

var Command = cli.Command{
	Name:    "experimental",
	Aliases: []string{"exp"},
	Subcommands: []*cli.Command{
		&request.Command,
	},
}
