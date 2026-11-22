package awsconfigfile

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/ini.v1"
)

type fakeSource struct {
	profiles []SSOProfile
	err      error
}

func (f fakeSource) GetProfiles(ctx context.Context) ([]SSOProfile, error) {
	return f.profiles, f.err
}

func TestGenerator_Generate(t *testing.T) {
	t.Run("merges profiles from all sources", func(t *testing.T) {
		cfg := ini.Empty()
		g := Generator{Config: cfg, NoCredentialProcess: true}
		g.AddSource(fakeSource{profiles: []SSOProfile{{AccountName: "a", RoleName: "r1"}}})
		g.AddSource(fakeSource{profiles: []SSOProfile{{AccountName: "b", RoleName: "r2"}}})

		err := g.Generate(context.Background())
		assert.NoError(t, err)
		assert.True(t, cfg.HasSection("profile a/r1"))
		assert.True(t, cfg.HasSection("profile b/r2"))
	})

	t.Run("defaults the profile name template", func(t *testing.T) {
		g := Generator{Config: ini.Empty()}
		assert.Equal(t, "", g.ProfileNameTemplate)
		err := g.Generate(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, DefaultProfileNameTemplate, g.ProfileNameTemplate)
	})

	t.Run("rejects illegal characters in prefix", func(t *testing.T) {
		g := Generator{Config: ini.Empty(), Prefix: "bad prefix"}
		err := g.Generate(context.Background())
		assert.ErrorContains(t, err, "illegal characters")
	})

	t.Run("rejects illegal characters in a custom profile template", func(t *testing.T) {
		g := Generator{Config: ini.Empty(), ProfileNameTemplate: `{{ .AccountName }}/"quoted"`}
		err := g.Generate(context.Background())
		assert.ErrorContains(t, err, "illegal characters")
	})

	t.Run("allows go template syntax containing otherwise-illegal characters", func(t *testing.T) {
		cfg := ini.Empty()
		g := Generator{
			Config:              cfg,
			ProfileNameTemplate: `{{ if eq .AccountName "prod" }}prod{{ else }}other{{ end }}/{{ .RoleName }}`,
			NoCredentialProcess: true,
		}
		g.AddSource(fakeSource{profiles: []SSOProfile{{AccountName: "prod", RoleName: "Admin"}}})

		err := g.Generate(context.Background())
		assert.NoError(t, err)
		assert.True(t, cfg.HasSection("profile prod/Admin"))
	})

	t.Run("propagates a source error", func(t *testing.T) {
		g := Generator{Config: ini.Empty()}
		g.AddSource(fakeSource{err: errors.New("source unavailable")})

		err := g.Generate(context.Background())
		assert.ErrorContains(t, err, "source unavailable")
	})

	t.Run("passes prune start urls through to Merge", func(t *testing.T) {
		cfg := ini.Empty()
		sec, err := cfg.NewSection("profile stale/Role")
		assert.NoError(t, err)
		_, err = sec.NewKey("granted_sso_start_url", "https://start.example.com")
		assert.NoError(t, err)
		_, err = sec.NewKey("granted_generated_from", "aws-sso")
		assert.NoError(t, err)

		g := Generator{Config: cfg, NoCredentialProcess: true, PruneStartURLs: []string{"https://start.example.com"}}

		err = g.Generate(context.Background())
		assert.NoError(t, err)
		assert.False(t, cfg.HasSection("profile stale/Role"))
	})
}

func TestGenerator_AddSource(t *testing.T) {
	g := Generator{}
	assert.Empty(t, g.Sources)
	g.AddSource(fakeSource{})
	g.AddSource(fakeSource{})
	assert.Len(t, g.Sources, 2)
}
