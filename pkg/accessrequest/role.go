// Package accessrequest handles
// making requests to roles that a
// user doesn't have access to.
package accessrequest

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/common-fate/clio/clierr"
	"github.com/fwdcloudsec/granted/pkg/config"
)

type Role struct {
	Account string `json:"account"`
	Role    string `json:"role"`
}

func (r Role) URL(dashboardURL string) string {
	u, err := url.Parse(dashboardURL)
	if err != nil {
		return fmt.Sprintf("error building access request URL: %s", err.Error())
	}
	u.Path = "access"
	q := u.Query()
	q.Add("type", "aws-sso")
	q.Add("permissionSetArn.label", r.Role)
	q.Add("accountId", r.Account)
	u.RawQuery = q.Encode()

	return u.String()
}

func (r Role) Save() error {
	roleBytes, err := json.Marshal(r)
	if err != nil {
		return err
	}

	configFolder, err := config.GrantedConfigFolder()
	if err != nil {
		return err
	}

	file := filepath.Join(configFolder, "latest-role")
	return os.WriteFile(file, roleBytes, 0644)
}

func LatestRole() (*Role, error) {
	configFolder, err := config.GrantedConfigFolder()
	if err != nil {
		return nil, err
	}

	file := filepath.Join(configFolder, "latest-role")

	if _, err := os.Stat(file); os.IsNotExist(err) {
		return nil, clierr.New("no latest role saved", clierr.Info("You can run 'assume' to try and access a role. If the role is inaccessible it will be saved as the latest role."))
	}

	roleBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var r Role
	err = json.Unmarshal(roleBytes, &r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

type Profile struct {
	Name string
}

func (p Profile) Save() error {
	profileBytes, err := json.Marshal(p)
	if err != nil {
		return err
	}

	configFolder, err := config.GrantedConfigFolder()
	if err != nil {
		return err
	}

	file := filepath.Join(configFolder, "latest-profile")
	return os.WriteFile(file, profileBytes, 0644)
}

func LatestProfile() (*Profile, error) {
	configFolder, err := config.GrantedConfigFolder()
	if err != nil {
		return nil, err
	}

	file := filepath.Join(configFolder, "latest-profile")

	if _, err := os.Stat(file); os.IsNotExist(err) {
		return nil, clierr.New("no latest profile saved", clierr.Info("You can run 'assume' to try and access a profile. If the profile is inaccessible it will be saved as the latest profile."))
	}

	profileBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var p Profile
	err = json.Unmarshal(profileBytes, &p)
	if err != nil {
		return nil, err
	}

	return &p, nil
}
