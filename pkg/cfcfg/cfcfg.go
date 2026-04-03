package cfcfg

import (
	"context"
	"fmt"
	"net/url"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	sdkconfig "github.com/common-fate/sdk/config"
)

func GetCommonFateURL(profile *cfaws.Profile) (*url.URL, error) {
	if profile == nil {
		clio.Debugw("skipping loading Common Fate SDK from URL", "reason", "profile was nil")
		return nil, nil
	}
	if profile.RawConfig == nil {
		clio.Debugw("skipping loading Common Fate SDK from URL", "reason", "profile.RawConfig was nil")
		return nil, nil
	}
	if !profile.RawConfig.HasKey("common_fate_url") {
		clio.Debugw("skipping loading Common Fate SDK from URL", "reason", "profile does not have key common_fate_url", "profile_keys", profile.RawConfig.KeyStrings())
		return nil, nil
	}
	key, err := profile.RawConfig.GetKey("common_fate_url")
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(key.Value())
	if err != nil {
		return nil, fmt.Errorf("invalid common_fate_url (%s): %w", key.Value(), err)
	}

	return u, nil
}

func GenerateRequestURL(apiURL string, requestID string) (string, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return "", err
	}
	p := u.JoinPath("access", "requests", requestID)
	return p.String(), nil
}

func Load(ctx context.Context, profile *cfaws.Profile) (*sdkconfig.Context, error) {
	cfURL, err := GetCommonFateURL(profile)
	if err != nil {
		return nil, err
	}

	if cfURL != nil {
		cfURL = cfURL.JoinPath("config.json")

		clio.Debugw("configuring Common Fate SDK from URL", "url", cfURL.String())

		return sdkconfig.New(ctx, sdkconfig.Opts{
			ConfigSources: []string{cfURL.String()},
		})
	} else {
		// if we can't load the Common Fate SDK config (e.g. if `~/.cf/config` is not present)
		// we can't request access through the Common Fate platform.
		return sdkconfig.LoadDefault(ctx)

	}
}

func LoadURL(ctx context.Context, cfURL string) (*sdkconfig.Context, error) {
	u, err := url.Parse(cfURL)
	if err != nil {
		return nil, err
	}
	u = u.JoinPath("config.json")

	clio.Debugw("configuring Common Fate SDK from URL", "url", u.String())

	return sdkconfig.New(ctx, sdkconfig.Opts{
		ConfigSources: []string{u.String()},
	})
}
