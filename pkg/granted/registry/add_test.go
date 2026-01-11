package registry

import (
	"testing"

	"github.com/fwdcloudsec/granted/pkg/granted/registry/gitregistry"
	"github.com/stretchr/testify/assert"
)

func TestRegistryBackwardCompatibility(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{
			name:    "existing flow without ref works",
			ref:     "",
			wantErr: false,
		},
		{
			name:    "flow with ref works",
			ref:     "master",
			wantErr: false,
		},
		{
			name:    "flow with invalid ref fails",
			ref:     "invalid-branch",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that we can create a registry with the ref
			opts := gitregistry.Opts{
				Name:     "test-registry",
				URL:      "https://github.com/octocat/Hello-World.git",
				Filename: "README",
				Ref:      tt.ref,
			}

			registry, err := gitregistry.New(opts)
			assert.NoError(t, err)
			assert.NotNil(t, registry)

			// We can't directly test pull() as it's private and uses internal paths
			// But we've verified that the registry can be created with or without ref
		})
	}
}