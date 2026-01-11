package autosync

import (
	"context"
	"time"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/granted/registry"
)

// interactive when false will fail the profile registry sync
// in case where user specific values that are defined in granted.yml's `templateValues` are not available.
// this is done so that users are aware of required keys when granted's credential-process is used through the AWS CLI.
func Run(ctx context.Context, interactive bool) {
	if registry.IsOutdatedConfig() {
		clio.Warn("Outdated Profile Registry Configuration. Use `granted registry migrate` to update your configuration.")

		clio.Warn("Skipping Profile Registry sync.")

		return
	}

	registries, err := registry.GetProfileRegistries(interactive)
	if err != nil {
		clio.Debugf("unable to load granted config file with err %s", err.Error())
		return
	}

	// check if registry has been configured or not.
	// should skip registry sync if no profile registry.
	if len(registries) == 0 {
		clio.Debug("profile registry not configured. Skipping auto sync.")
		return
	}

	// load and check if sync has been run for the day. If true then skip.
	rc, ok := loadRegistryConfig()
	clio.Debug("checking if autosync has been run for the day")
	if ok && time.Now().Weekday() == rc.LastCheckForSync {
		clio.Debug("skipping profile registry sync until tomorrow=%s", rc.Path())
		return
	}

	err = runSync(ctx, rc, interactive)
	if err != nil {
		clio.Warnf("Failed to sync Profile Registries: %s", err.Error())
	}
}
