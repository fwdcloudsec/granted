package granted

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/urfave/cli/v2"
)

var CacheCommand = cli.Command{
	Name:        "cache",
	Usage:       "Manage your cached credentials that are stored in secure storage",
	Subcommands: []*cli.Command{&clearCommand, &listCommand},
}

var listCommand = cli.Command{
	Name:  "list",
	Usage: "List currently cached credentials and secure storage type",
	Action: func(c *cli.Context) error {
		storageToNameMap := map[string]securestorage.SecureStorage{
			"aws-iam-credentials": securestorage.NewSecureIAMCredentialStorage().SecureStorage,
			"sso-token":           securestorage.NewSecureSSOTokenStorage().SecureStorage,
			"session-credentials": securestorage.NewSecureSessionCredentialStorage().SecureStorage,
		}

		tw := tabwriter.NewWriter(os.Stderr, 10, 1, 5, ' ', 0)
		headers := strings.Join([]string{"STORAGE TYPE", "KEY"}, "\t")
		_, _ = fmt.Fprintln(tw, headers)

		for storageName, v := range storageToNameMap {

			keys, err := v.ListKeys()
			if err != nil {
				return err
			}

			for _, key := range keys {
				tabbed := strings.Join([]string{storageName, key}, "\t")
				_, _ = fmt.Fprintln(tw, tabbed)
			}

		}

		_ = tw.Flush()

		return nil
	},
}

var clearCommand = cli.Command{
	Name:  "clear",
	Usage: "Clear cached credential from the secure storage",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "all", Usage: "clears all of the cached credentials from all secure storage"},
		&cli.StringFlag{Name: "storage", Usage: "Specify the storage type"},
	},
	Action: func(c *cli.Context) error {
		storageToNameMap := map[string]securestorage.SecureStorage{
			"aws-iam-credentials": securestorage.NewSecureIAMCredentialStorage().SecureStorage,
			"sso-token":           securestorage.NewSecureSSOTokenStorage().SecureStorage,
			"session-credentials": securestorage.NewSecureSessionCredentialStorage().SecureStorage,
		}

		clearAll := c.Bool("all")

		if clearAll {
			for name, storage := range storageToNameMap {
				keys, err := storage.ListKeys()
				if err != nil {
					return err
				}
				if len(keys) == 0 {
					continue
				}
				for _, key := range keys {
					err = storage.Clear(key)
					if err != nil {
						return err
					}
				}
				clio.Debugw("clear flag provided clearing cache for all credentials in storage", "storage", name)
			}
			clio.Infow("cleared cache for all credentials in storage", "storage", "all")
			return nil
		}

		selection := c.String("storage")

		// store the credentials in secure storage
		selectedStorage, ok := storageToNameMap[selection]
		if !ok {
			return errors.New("please specify a valid storage to clear using --storage, for example: '--storage=session-credentials'. valid storages are: [aws-iam-credentials, sso-token, session-credentials]")
		}

		keys, err := selectedStorage.ListKeys()
		if err != nil {
			return err
		}

		for _, key := range keys {
			clio.Infow("clearing cache", "storage", selectedStorage, "key", key)
			err = selectedStorage.Clear(key)
			if err != nil {
				return err
			}
		}

		clio.Successf("cleared %v cache entries from %s", len(keys), selection)

		return nil
	},
}
