package cfaws

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testLoginSession = "arn:aws:iam::123456789012:user/alice"
	testLoginRoleARN = "arn:aws:iam::123456789012:role/dev"

	testLoginSharedConfig = `[profile login-prof]
login_session = ` + testLoginSession + `
region = us-east-1

[profile dev-role]
role_arn = ` + testLoginRoleARN + `
source_profile = login-prof
duration_seconds = 1800

[profile plain-iam]
region = us-east-1

[profile managed-login]
granted_login_session = ` + testLoginSession + `
credential_process = granted credential-process --profile=managed-login
region = us-east-1

[profile managed-role]
role_arn = ` + testLoginRoleARN + `
source_profile = managed-login

[profile managed-nocp]
granted_login_session = ` + testLoginSession + `
region = eu-west-1
`
)

// writeLoginFixtures writes an isolated shared config with an `aws login` profile and
// a role chained from it, points every relevant lookup at temporary locations, and
// loads the profiles.
func writeLoginFixtures(t *testing.T) *Profiles {
	t.Helper()
	writeSharedConfig(t, testLoginSharedConfig)
	// The gimme-aws-creds matcher runs first and reads the Okta config from the home
	// directory; point it somewhere empty so a developer's real config can't match.
	t.Setenv("OKTA_CONFIG", filepath.Join(t.TempDir(), "missing-okta-config"))
	t.Setenv("AWS_LOGIN_CACHE_DIRECTORY", t.TempDir())

	profiles, err := LoadProfiles()
	require.NoError(t, err)
	return profiles
}

func loadTestProfile(t *testing.T, name string) *Profile {
	t.Helper()
	profiles := writeLoginFixtures(t)
	p, err := profiles.LoadInitialisedProfile(context.Background(), name)
	require.NoError(t, err)
	return p
}

// The SDK refuses an `aws login` profile as a source_profile, so without Granted's
// fallback the chained profile fails to load at all.
func TestLoadProfiles_RoleChainedFromLoginSource(t *testing.T) {
	ctx := context.Background()
	profiles := writeLoginFixtures(t)

	root, err := profiles.LoadInitialisedProfile(ctx, "login-prof")
	require.NoError(t, err)
	assert.Empty(t, root.Parents)
	assert.Equal(t, testLoginSession, root.AWSConfig.LoginSession)

	child, err := profiles.LoadInitialisedProfile(ctx, "dev-role")
	require.NoError(t, err)
	require.Len(t, child.Parents, 1)
	assert.Equal(t, "login-prof", child.Parents[0].Name)
	assert.Equal(t, root.ProfileType, child.ProfileType)
	assert.Equal(t, testLoginRoleARN, child.AWSConfig.RoleARN)
	assert.Equal(t, "login-prof", child.AWSConfig.SourceProfileName)
	require.NotNil(t, child.AWSConfig.RoleDurationSeconds)
	assert.Equal(t, 30*time.Minute, *child.AWSConfig.RoleDurationSeconds)
	region, err := child.Region(ctx)
	require.NoError(t, err)
	assert.Equal(t, "us-east-1", region)
}

func TestSharedConfigFromRawSection(t *testing.T) {
	writeSharedConfig(t, testLoginSharedConfig)
	profiles, err := LoadProfiles()
	require.NoError(t, err)
	raw, err := profiles.Profile("dev-role")
	require.NoError(t, err)

	cfg, err := sharedConfigFromRawSection("dev-role", raw.RawConfig)
	require.NoError(t, err)
	assert.Equal(t, "dev-role", cfg.Profile)
	assert.Equal(t, testLoginRoleARN, cfg.RoleARN)
	assert.Equal(t, "login-prof", cfg.SourceProfileName)
	require.NotNil(t, cfg.RoleDurationSeconds)
	assert.Equal(t, 30*time.Minute, *cfg.RoleDurationSeconds)
	assert.False(t, cfg.Credentials.HasKeys())

	_, err = sharedConfigFromRawSection("missing", nil)
	assert.Error(t, err)

	assert.True(t, profiles.sourceIsLoginProfile("login-prof"))
	assert.False(t, profiles.sourceIsLoginProfile("dev-role"))
	assert.False(t, profiles.sourceIsLoginProfile("nope"))
}
