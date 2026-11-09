package registry

import (
	"os"
	"path/filepath"
	"testing"

	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/granted/registry/gitregistry"
	"github.com/fwdcloudsec/granted/pkg/httpregistry"
	"github.com/stretchr/testify/assert"
)

func withTempGrantedHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // windows
	assert.NoError(t, os.MkdirAll(filepath.Join(home, ".dgranted"), 0700))
}

func saveRegistries(t *testing.T, registries []grantedConfig.Registry) {
	t.Helper()
	cfg, err := grantedConfig.Load()
	assert.NoError(t, err)
	cfg.ProfileRegistry.Registries = registries
	assert.NoError(t, cfg.Save())
}

func TestGetProfileRegistries_Empty(t *testing.T) {
	withTempGrantedHome(t)

	got, err := GetProfileRegistries(false)
	assert.NoError(t, err)
	assert.Empty(t, got)
}

func TestGetProfileRegistries_BuildsCorrectRegistryTypes(t *testing.T) {
	withTempGrantedHome(t)
	saveRegistries(t, []grantedConfig.Registry{
		{Name: "git-registry", URL: "https://github.com/example/registry.git", Type: "git"},
		{Name: "default-type-registry", URL: "https://github.com/example/other.git"}, // Type omitted defaults to git
		{Name: "http-registry", URL: "https://provider.example.com", Type: "http", TenantID: "tenant-1"},
	})

	got, err := GetProfileRegistries(false)
	assert.NoError(t, err)
	assert.Len(t, got, 3)

	byName := map[string]loadedRegistry{}
	for _, r := range got {
		byName[r.Config.Name] = r
	}

	_, ok := byName["git-registry"].Registry.(*gitregistry.Registry)
	assert.True(t, ok, "expected git-registry to be a *gitregistry.Registry")

	_, ok = byName["default-type-registry"].Registry.(*gitregistry.Registry)
	assert.True(t, ok, "expected empty Type to default to a *gitregistry.Registry")

	_, ok = byName["http-registry"].Registry.(*httpregistry.Registry)
	assert.True(t, ok, "expected http-registry to be a *httpregistry.Registry")
}

func TestGetProfileRegistries_SortsByPriorityDescending(t *testing.T) {
	withTempGrantedHome(t)
	saveRegistries(t, []grantedConfig.Registry{
		{Name: "low", URL: "https://github.com/example/low.git", Type: "git", Priority: 1},
		{Name: "high", URL: "https://github.com/example/high.git", Type: "git", Priority: 10},
		{Name: "mid", URL: "https://github.com/example/mid.git", Type: "git", Priority: 5},
	})

	got, err := GetProfileRegistries(false)
	assert.NoError(t, err)
	if assert.Len(t, got, 3) {
		assert.Equal(t, "high", got[0].Config.Name)
		assert.Equal(t, "mid", got[1].Config.Name)
		assert.Equal(t, "low", got[2].Config.Name)
	}
}
