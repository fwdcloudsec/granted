package cfaws

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

// writeSharedConfig writes contents to a temporary shared config file and points
// the SDK at it, isolating the test from the developer's own AWS configuration.
func writeSharedConfig(t *testing.T, contents string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials"))
}

func TestLoadSSOConfig(t *testing.T) {
	const sharedConfig = `[profile dualstack]
region = eu-west-1
use_dualstack_endpoint = true

[profile legacy]
region = eu-west-1
`

	tests := []struct {
		name    string
		env     string
		profile string
		want    aws.DualStackEndpointState
	}{
		{"profile opts in", "", "dualstack", aws.DualStackEndpointStateEnabled},
		{"profile does not opt in", "", "legacy", aws.DualStackEndpointStateUnset},
		{"environment opts in", "true", "", aws.DualStackEndpointStateEnabled},
		{"unknown profile falls back to the environment", "true", "missing", aws.DualStackEndpointStateEnabled},
		{"nothing opts in", "", "", aws.DualStackEndpointStateUnset},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeSharedConfig(t, sharedConfig)
			t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", tt.env)

			cfg := LoadSSOConfig(context.Background(), "eu-west-1", tt.profile)
			if cfg.Region != "eu-west-1" {
				t.Errorf("region = %q, want eu-west-1", cfg.Region)
			}

			got := ssooidc.NewFromConfig(cfg).Options().EndpointOptions.UseDualStackEndpoint
			if got != tt.want {
				t.Errorf("UseDualStackEndpoint = %v, want %v", got, tt.want)
			}
		})
	}
}
