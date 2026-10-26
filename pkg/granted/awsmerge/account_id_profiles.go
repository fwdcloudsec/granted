package awsmerge

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"gopkg.in/ini.v1"
)

var (
	roleARNRegex   = regexp.MustCompile(`^arn:[^:]+:iam::(\d{12}):role/(.+)$`)
	accountIDRegex = regexp.MustCompile(`^\d{12}$`)
)

// accountProfile is a profile synced from a registry along with the
// AWS account ID and role name that it resolves to.
type accountProfile struct {
	section   *ini.Section
	accountID string
	roleName  string
}

// profileAccountAndRole returns the AWS account ID and role name for a profile section.
//
// The account ID is read from 'role_arn' if present, otherwise from 'sso_account_id'
// or 'granted_sso_account_id'. The role name is read from 'role_arn' if present,
// otherwise from 'sso_role_name' or 'granted_sso_role_name'.
//
// An empty account ID is returned if the profile does not reference a valid 12-digit account ID.
func profileAccountAndRole(sec *ini.Section) (accountID string, roleName string) {
	if sec.HasKey("role_arn") {
		matches := roleARNRegex.FindStringSubmatch(strings.TrimSpace(sec.Key("role_arn").Value()))
		if matches != nil {
			accountID = matches[1]
			// strip any IAM path, e.g. 'role/path/to/MyRole' -> 'MyRole'
			parts := strings.Split(matches[2], "/")
			roleName = parts[len(parts)-1]
		}
	}

	if accountID == "" {
		for _, key := range []string{"sso_account_id", "granted_sso_account_id"} {
			if sec.HasKey(key) {
				accountID = strings.TrimSpace(sec.Key(key).Value())
				break
			}
		}
	}

	if roleName == "" {
		for _, key := range []string{"sso_role_name", "granted_sso_role_name"} {
			if sec.HasKey(key) {
				roleName = strings.TrimSpace(sec.Key(key).Value())
				break
			}
		}
	}

	if !accountIDRegex.MatchString(accountID) {
		return "", ""
	}

	return accountID, roleName
}

// addAccountIDProfiles adds a copy of each of the 'profiles' to 'dst', named after
// the AWS account ID of the profile, so that the profile can be assumed by account ID.
//
// If an account has a single profile in the registry, the copy is named '<account ID>'.
// If an account has more than one profile, each copy is named '<account ID>/<role name>'.
// If 'opts.PrefixAllProfiles' is set, the registry name is prefixed to the copy, as it
// is for the other profiles in the registry.
//
// Copies which would clash with an existing profile are skipped with a warning,
// as are profiles which don't reference an AWS account ID.
func addAccountIDProfiles(dst *ini.File, profiles []*ini.Section, opts RegistryOpts) error {
	var accountIDs []string
	byAccount := map[string][]accountProfile{}

	for _, sec := range profiles {
		accountID, roleName := profileAccountAndRole(sec)
		if accountID == "" {
			clio.Debugf("not adding an account ID profile for %s: no AWS account ID found", sec.Name())
			continue
		}

		if _, ok := byAccount[accountID]; !ok {
			accountIDs = append(accountIDs, accountID)
		}
		byAccount[accountID] = append(byAccount[accountID], accountProfile{
			section:   sec,
			accountID: accountID,
			roleName:  roleName,
		})
	}

	for _, accountID := range accountIDs {
		accountProfiles := byAccount[accountID]

		for _, p := range accountProfiles {
			originalName := strings.TrimPrefix(p.section.Name(), "profile ")

			name := accountID
			if len(accountProfiles) > 1 {
				if p.roleName == "" {
					clio.Warnf("not adding an account ID profile for %s: account %s has more than one profile and no role name was found", originalName, accountID)
					continue
				}
				name = accountID + "/" + p.roleName
			}

			if opts.PrefixAllProfiles {
				name = opts.Name + "." + name
			}

			if !cfaws.IsLegalProfileName(name) {
				continue
			}

			sectionName := "profile " + name

			if contains(dst.SectionStrings(), sectionName) {
				clio.Warnf("not adding account ID profile %s for %s: a profile with this name already exists", name, originalName)
				continue
			}

			f, err := dst.NewSection(sectionName)
			if err != nil {
				return err
			}

			// the source section has already had any template variables interpolated,
			// so the keys are copied as they are. A 'credential_process' entry continues to
			// reference the original profile, so both profiles share the same credentials.
			err = copySection(copySectionOpts{
				Src: p.section,
				Dst: f,
			})
			if err != nil {
				return err
			}

			f.Comment = fmt.Sprintf("# account ID profile for %s", originalName)
		}
	}

	return nil
}
