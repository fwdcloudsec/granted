package granted

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/fwdcloudsec/granted/pkg/testable"
	"github.com/urfave/cli/v2"
)

// TokenCommand has been deprecated in favour of 'sso-tokens'
// @TODO: remove this when suitable after deprecation
var TokenCommand = cli.Command{
	Name:  "token",
	Usage: "Deprecated: Use 'sso-tokens' instead",
	Action: func(ctx *cli.Context) error {
		fmt.Println("The 'token' command has been deprecated and will be removed in a future release, it has been renamed to 'sso-tokens'")
		return SSOTokensCommand.Run(ctx)
	},
}
var SSOTokensCommand = cli.Command{
	Name:        "sso-tokens",
	Usage:       "Manage AWS SSO tokens",
	Subcommands: []*cli.Command{&ListSSOTokensCommand, &ClearSSOTokensCommand, &TokenExpiryCommand},
	Action:      ListSSOTokensCommand.Action,
}

var ListSSOTokensCommand = cli.Command{
	Name:  "list",
	Usage: "Lists all access tokens saved in the keyring",
	Action: func(ctx *cli.Context) error {

		startUrlMap, err := MapTokens(ctx.Context)
		if err != nil {
			return err
		}

		var max int
		for k := range startUrlMap {
			if len(k) > max {
				max = len(k)
			}
		}
		secureSSOTokenStorage := securestorage.NewSecureSSOTokenStorage()
		keys, err := secureSSOTokenStorage.SecureStorage.ListKeys()
		if err != nil {
			return err
		}

		for _, key := range keys {
			clio.Logf("%-*s (%s)", max, key, strings.Join(startUrlMap[key], ", "))
		}
		return nil
	},
}

var TokenExpiryCommand = cli.Command{
	Name:  "expiry",
	Usage: "Lists expiry status for all access tokens saved in the keyring",
	Flags: []cli.Flag{&cli.StringFlag{Name: "url", Usage: "If provided, prints the expiry of the token for the specific SSO URL"},
		&cli.BoolFlag{Name: "json", Usage: "If provided, prints the expiry of the tokens in JSON"}},
	Action: func(c *cli.Context) error {
		url := c.String("url")
		ctx := c.Context

		secureSSOTokenStorage := securestorage.NewSecureSSOTokenStorage()

		if url != "" {
			token := secureSSOTokenStorage.GetValidSSOToken(ctx, url)

			var expiry string
			if token == nil {
				return errors.New("SSO token is expired")
			}
			expiry = token.Expiry.Local().Format(time.RFC3339)
			fmt.Println(expiry)

			return nil
		}

		startUrlMap, err := MapTokens(ctx)
		if err != nil {
			return err
		}

		var max int
		for k := range startUrlMap {
			if len(k) > max {
				max = len(k)
			}
		}

		keys, err := secureSSOTokenStorage.SecureStorage.ListKeys()
		if err != nil {
			return err
		}

		jsonflag := c.Bool("json")

		type sso_expiry struct {
			StartURLs string `json:"start_urls"`
			ExpiresAt string `json:"expires_at"`
			IsExpired bool   `json:"is_expired"`
		}

		var jsonDataArray []sso_expiry

		for _, key := range keys {
			token := secureSSOTokenStorage.GetValidSSOToken(ctx, key)

			var expiry string
			if token == nil {
				expiry = "EXPIRED"
			} else {
				expiry = token.Expiry.Local().Format(time.RFC3339)
			}
			if jsonflag {
				sso_expiry_data := sso_expiry{
					StartURLs: key,
					ExpiresAt: expiry,
					IsExpired: expiry == "EXPIRED",
				}
				jsonDataArray = append(jsonDataArray, sso_expiry_data)
			} else {
				clio.Logf("%-*s (%s) expires at: %s", max, key, strings.Join(startUrlMap[key], ", "), expiry)
			}
		}

		if jsonflag {
			jsonData, err := json.Marshal(jsonDataArray)
			if err != nil {
				return err
			}
			fmt.Println(string(jsonData))
		}

		return nil
	},
}

// granted token -> lists all tokens
// granted token list -> lists all tokens
// granted token clear -> prompts for selection // prompt confirm?
// granted token clear --all or -a -> clear all
// granted token clear profilename -> clear profile
// granted token clear profilename --confirm -> skip confirm prompt

func MapTokens(ctx context.Context) (map[string][]string, error) {
	secureSSOTokenStorage := securestorage.NewSecureSSOTokenStorage()
	keys, err := secureSSOTokenStorage.SecureStorage.ListKeys()
	if err != nil {
		return nil, err
	}

	profiles, err := cfaws.LoadProfiles()
	if err != nil {
		return nil, err
	}
	profiles.InitialiseProfilesTree(ctx)
	startUrlMap := make(map[string][]string)
	for _, k := range keys {
		startUrlMap[k] = []string{}
	}
	a := &cfaws.AwsSsoAssumer{}
	for _, name := range profiles.ProfileNames {
		if p, _ := profiles.Profile(name); p.ProfileType == a.Type() {
			ssoUrl := p.AWSConfig.SSOStartURL
			if len(p.Parents) != 0 {
				ssoUrl = p.Parents[0].AWSConfig.SSOStartURL
			}
			// Don't add any profiles which are not in the keyring already
			if _, ok := startUrlMap[ssoUrl]; ok {
				startUrlMap[ssoUrl] = append(startUrlMap[ssoUrl], p.Name)
			}
		}
	}
	return startUrlMap, nil
}

var ClearSSOTokensCommand = cli.Command{
	Name:  "clear",
	Usage: "Remove a selected token from the keyring",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "all", Aliases: []string{"a"}, Usage: "Remove all saved tokens from keyring"},
	},
	Action: func(c *cli.Context) error {

		if c.Bool("all") {
			err := clearAllTokens()
			if err != nil {
				return err
			}
			clio.Success("Cleared all saved tokens")
			return nil
		}
		var selection string

		if c.Args().First() != "" {
			selection = c.Args().First()
		}

		startUrlMap, err := MapTokens(c.Context)
		if err != nil {
			return err
		}
		if selection == "" {
			var max int
			for k := range startUrlMap {
				if len(k) > max {
					max = len(k)
				}
			}
			selectionsMap := make(map[string]string)
			tokenList := []string{}
			for k, profiles := range startUrlMap {
				stringKey := fmt.Sprintf("%-*s (%s)", max, k, strings.Join(profiles, ", "))
				tokenList = append(tokenList, stringKey)
				selectionsMap[stringKey] = k
			}
			withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
			in := survey.Select{
				Message: "Select a token to remove from keyring",
				Options: tokenList,
			}
			clio.NewLine()
			var out string
			err = testable.AskOne(&in, &out, withStdio)
			if err != nil {
				return err
			}
			selection = selectionsMap[out]
		}

		secureSSOTokenStorage := securestorage.NewSecureSSOTokenStorage()

		err = secureSSOTokenStorage.SecureStorage.Clear(selection)
		if err != nil {
			return err
		}
		clio.Successf("Cleared %s", selection)
		return nil
	},
}

// clearAllTokens calls clearToken for each key in the keyring
func clearAllTokens() error {
	secureSSOTokenStorage := securestorage.NewSecureSSOTokenStorage()
	keys, err := secureSSOTokenStorage.SecureStorage.ListKeys()
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := secureSSOTokenStorage.SecureStorage.Clear(k); err != nil {
			return err
		}
	}
	return nil
}
