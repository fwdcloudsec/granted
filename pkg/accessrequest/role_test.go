package accessrequest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// withTempGrantedHome redirects GrantedConfigFolder() at a temp directory
// (and pre-creates the .dgranted folder it resolves to) so these tests never
// touch the developer's real ~/.dgranted.
func withTempGrantedHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // windows
	assert.NoError(t, os.MkdirAll(filepath.Join(home, ".dgranted"), 0700))
}

func TestRole_URL(t *testing.T) {
	r := Role{Account: "123456789012", Role: "Admin"}
	got := r.URL("https://access.example.com")

	assert.Contains(t, got, "https://access.example.com/access?")
	assert.Contains(t, got, "type=aws-sso")
	assert.Contains(t, got, "accountId=123456789012")
	assert.Contains(t, got, "permissionSetArn.label=Admin")
}

func TestRole_URL_InvalidDashboardURL(t *testing.T) {
	r := Role{Account: "123456789012", Role: "Admin"}
	got := r.URL("://not-a-url")
	assert.Contains(t, got, "error building access request URL")
}

func TestRole_SaveAndLatestRole(t *testing.T) {
	withTempGrantedHome(t)

	r := Role{Account: "123456789012", Role: "Admin"}
	assert.NoError(t, r.Save())

	got, err := LatestRole()
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, r, *got)
	}
}

func TestLatestRole_NoneSaved(t *testing.T) {
	withTempGrantedHome(t)

	got, err := LatestRole()
	assert.Nil(t, got)
	assert.ErrorContains(t, err, "no latest role saved")
}

func TestProfile_SaveAndLatestProfile(t *testing.T) {
	withTempGrantedHome(t)

	p := Profile{Name: "my-profile"}
	assert.NoError(t, p.Save())

	got, err := LatestProfile()
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, p, *got)
	}
}

func TestLatestProfile_NoneSaved(t *testing.T) {
	withTempGrantedHome(t)

	got, err := LatestProfile()
	assert.Nil(t, got)
	assert.ErrorContains(t, err, "no latest profile saved")
}
