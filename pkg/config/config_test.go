package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/fwdcloudsec/granted/internal/build"
	"github.com/stretchr/testify/require"
)

func isolateConfigEnvironment(t *testing.T) string {
	t.Helper()
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)
	t.Setenv("USERPROFILE", testHome)
	t.Setenv("GRANTED_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	return testHome
}

func TestGrantedConfigFilePathDefaults(t *testing.T) {
	for _, scenario := range []string{"unset", "empty", "xdg", "home-before-xdg"} {
		t.Run(scenario, func(t *testing.T) {
			testHome := isolateConfigEnvironment(t)
			if scenario == "unset" {
				require.NoError(t, os.Unsetenv("GRANTED_CONFIG"))
			}
			defaultDir := filepath.Join(testHome, build.ConfigFolderName)
			want := filepath.Join(defaultDir, "config")
			if scenario == "xdg" || scenario == "home-before-xdg" {
				xdgDir := t.TempDir()
				t.Setenv("XDG_CONFIG_HOME", xdgDir)
				if scenario == "home-before-xdg" {
					require.NoError(t, os.Mkdir(defaultDir, 0700))
				} else {
					want = filepath.Join(xdgDir, "granted", "config")
				}
			}

			got, err := GrantedConfigFilePath()
			require.NoError(t, err)
			require.Equal(t, want, filepath.Clean(got))
		})
	}
}

func TestGrantedConfigFilePathOverride(t *testing.T) {
	testHome := isolateConfigEnvironment(t)
	require.NoError(t, os.Mkdir(filepath.Join(testHome, build.ConfigFolderName), 0700))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	for _, configPath := range []string{
		filepath.Join(t.TempDir(), "team config.toml"),
		filepath.Join("team", "config.toml"),
		"~/config.toml",
		"$HOME/config.toml",
	} {
		t.Run(configPath, func(t *testing.T) {
			t.Setenv("GRANTED_CONFIG", configPath)
			got, err := GrantedConfigFilePath()
			require.NoError(t, err)
			require.Equal(t, configPath, got)
		})
	}

	t.Run("before XDG config", func(t *testing.T) {
		isolateConfigEnvironment(t)
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		configPath := filepath.Join(t.TempDir(), "custom.toml")
		t.Setenv("GRANTED_CONFIG", configPath)
		got, err := GrantedConfigFilePath()
		require.NoError(t, err)
		require.Equal(t, configPath, got)
	})

	t.Run("without home directory", func(t *testing.T) {
		t.Setenv("HOME", "")
		t.Setenv("USERPROFILE", "")
		configPath := filepath.Join(testHome, "custom.toml")
		t.Setenv("GRANTED_CONFIG", configPath)
		got, err := GrantedConfigFilePath()
		require.NoError(t, err)
		require.Equal(t, configPath, got)
	})
}

func TestConfigOverrideLoadSave(t *testing.T) {
	testHome := isolateConfigEnvironment(t)
	defaultDir := filepath.Join(testHome, build.ConfigFolderName)
	require.NoError(t, os.Mkdir(defaultDir, 0700))
	defaultPath := filepath.Join(defaultDir, "config")
	defaultContent := []byte("DefaultBrowser = 'firefox'\nDisableUsageTips = true\n")
	require.NoError(t, os.WriteFile(defaultPath, defaultContent, 0600))

	customDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(customDir, "custom.toml"), []byte("DefaultBrowser = 'chrome'\n"), 0600))
	t.Chdir(customDir)
	t.Setenv("GRANTED_CONFIG", "custom.toml")

	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, "chrome", cfg.DefaultBrowser)
	require.False(t, cfg.DisableUsageTips, "default file settings must not be merged")
	cfg.DefaultBrowser = "safari"
	require.NoError(t, cfg.Save())

	reloaded, err := Load()
	require.NoError(t, err)
	require.Equal(t, "safari", reloaded.DefaultBrowser)
	unchanged, err := os.ReadFile(defaultPath)
	require.NoError(t, err)
	require.Equal(t, defaultContent, unchanged)
}

func TestConfigOverrideCreatesFile(t *testing.T) {
	for _, operation := range []string{"load", "save"} {
		t.Run(operation, func(t *testing.T) {
			isolateConfigEnvironment(t)
			configPath := filepath.Join(t.TempDir(), "new.toml")
			t.Setenv("GRANTED_CONFIG", configPath)
			want := NewDefaultConfig()
			if operation == "save" {
				want.DefaultBrowser = "chrome"
				require.NoError(t, want.Save())
			}
			got, err := Load()
			require.NoError(t, err)
			require.Equal(t, want, *got)
			info, err := os.Stat(configPath)
			require.NoError(t, err)
			if runtime.GOOS != "windows" {
				require.Equal(t, os.FileMode(0600), info.Mode().Perm())
			}
		})
	}
}

func TestConfigOverrideErrors(t *testing.T) {
	for _, scenario := range []string{"missing parent", "directory", "invalid TOML"} {
		t.Run(scenario, func(t *testing.T) {
			testHome := isolateConfigEnvironment(t)
			defaultDir := filepath.Join(testHome, build.ConfigFolderName)
			require.NoError(t, os.Mkdir(defaultDir, 0700))
			defaultPath := filepath.Join(defaultDir, "config")
			defaultContent := []byte("DefaultBrowser = 'firefox'\n")
			require.NoError(t, os.WriteFile(defaultPath, defaultContent, 0600))
			customDir := t.TempDir()
			configPath := customDir
			switch scenario {
			case "missing parent":
				configPath = filepath.Join(customDir, "missing", "config.toml")
			case "invalid TOML":
				configPath = filepath.Join(customDir, "invalid.toml")
				require.NoError(t, os.WriteFile(configPath, []byte("DefaultBrowser = ["), 0600))
			}
			t.Setenv("GRANTED_CONFIG", configPath)

			cfg, err := Load()
			require.Error(t, err)
			require.Nil(t, cfg)
			if scenario != "invalid TOML" {
				defaults := NewDefaultConfig()
				require.Error(t, defaults.Save())
			}
			if scenario == "missing parent" {
				_, err := os.Stat(filepath.Dir(configPath))
				require.True(t, os.IsNotExist(err), "missing parent must not be created")
			}
			unchanged, err := os.ReadFile(defaultPath)
			require.NoError(t, err)
			require.Equal(t, defaultContent, unchanged)
		})
	}
}

func TestConfigOverridePreservesStorageFolders(t *testing.T) {
	testHome := isolateConfigEnvironment(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(testHome, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(testHome, "cache"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(testHome, "state"))
	for _, resolver := range []func() (string, error){GrantedConfigFolder, GrantedCacheFolder, GrantedStateFolder} {
		before, err := resolver()
		require.NoError(t, err)
		t.Setenv("GRANTED_CONFIG", filepath.Join(t.TempDir(), "custom.toml"))
		after, err := resolver()
		require.NoError(t, err)
		require.Equal(t, before, after)
		t.Setenv("GRANTED_CONFIG", "")
	}
}
