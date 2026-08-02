package cfaws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/common-fate/clio"
)

// LoadSSOConfig loads the shared AWS configuration for the sso and ssooidc
// clients, which ignore settings such as use_dualstack_endpoint unless the
// config records the sources it was read from. profile may be empty, and
// loading is best effort.
func LoadSSOConfig(ctx context.Context, region string, profile string) aws.Config {
	if profile != "" {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithSharedConfigProfile(profile))
		if err == nil {
			return cfg
		}
		clio.Debugw("could not load shared config for profile, falling back to the default profile", "profile", profile, "error", err)
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		clio.Debugw("could not load shared config, endpoint settings will be ignored", "error", err)
		return aws.Config{Region: region}
	}
	return cfg
}
