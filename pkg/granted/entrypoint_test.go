package granted

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestDeprecatedLoginCommand(t *testing.T) {
	app := &cli.App{Commands: []*cli.Command{&login}}
	err := app.Run([]string{"granted", "login"})
	assert.NoError(t, err)
}
