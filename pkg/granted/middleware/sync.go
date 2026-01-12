package middleware

import (
	"github.com/fwdcloudsec/granted/pkg/autosync"
	"github.com/urfave/cli/v2"
)

func WithAutosync() cli.BeforeFunc {
	return func(c *cli.Context) error {
		autosync.Run(c.Context, false)
		return nil
	}
}
