// Package awsconfigfile contains logic to template ~/.aws/config files
// based on profile sources (AWS SSO, HTTP registries, etc).
//
// Vendored from github.com/common-fate/awsconfigfile v0.10.0 and updated
// to use provider-agnostic naming.
package awsconfigfile

import (
	"bytes"
	"sort"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"gopkg.in/ini.v1"
)

type SSOProfile struct {
	SSOStartURL string
	SSORegion   string

	Region      string
	AccountID   string
	AccountName string
	RoleName    string
	ProviderURL string
	// GeneratedFrom is the source that the profile was created from,
	// such as 'aws-sso' or a named HTTP registry.
	GeneratedFrom string
}

// ToIni converts a profile to a struct with `ini` tags ready to be
// written to an ini config file.
//
// If noCredentialProcess is true, the struct will contain sso_ parameters.
// Otherwise it will contain granted_sso parameters for use with the
// Granted credential process.
func (p SSOProfile) ToIni(profileName string, noCredentialProcess bool) any {
	if noCredentialProcess {
		return &regularProfile{
			SSOStartURL:   p.SSOStartURL,
			SSORegion:     p.SSORegion,
			SSOAccountID:  p.AccountID,
			SSORoleName:   p.RoleName,
			GeneratedFrom: p.GeneratedFrom,
			Region:        p.Region,
		}
	}

	credProcess := "granted credential-process --profile " + profileName

	if p.ProviderURL != "" {
		credProcess += " --url " + p.ProviderURL
	}

	return &credentialProcessProfile{
		SSOStartURL:   p.SSOStartURL,
		SSORegion:     p.SSORegion,
		SSOAccountID:  p.AccountID,
		SSORoleName:   p.RoleName,
		CredProcess:   credProcess,
		GeneratedFrom: p.GeneratedFrom,
		Region:        p.Region,
	}
}

type MergeOpts struct {
	Config              *ini.File
	Prefix              string
	Profiles            []SSOProfile
	SectionNameTemplate string
	NoCredentialProcess bool
	// PruneStartURLs is a slice of AWS SSO start URLs which profiles are being
	// generated for. Existing profiles with these start URLs will be removed if
	// they aren't found in the Profiles field.
	PruneStartURLs []string
}

func Merge(opts MergeOpts) error {
	if opts.SectionNameTemplate == "" {
		opts.SectionNameTemplate = "{{ .AccountName }}/{{ .RoleName }}"
	}

	sort.SliceStable(opts.Profiles, func(i, j int) bool {
		combinedNameI := opts.Profiles[i].AccountName + "/" + opts.Profiles[i].RoleName
		combinedNameJ := opts.Profiles[j].AccountName + "/" + opts.Profiles[j].RoleName
		return combinedNameI < combinedNameJ
	})

	funcMap := sprig.TxtFuncMap()
	sectionNameTempl, err := template.New("").Funcs(funcMap).Parse(opts.SectionNameTemplate)
	if err != nil {
		return err
	}

	// remove any config sections that have 'common_fate_generated_from' as a key
	// (legacy) or 'granted_generated_from' (current)
	for _, sec := range opts.Config.Sections() {
		var startURL string

		if sec.HasKey("granted_sso_start_url") {
			startURL = sec.Key("granted_sso_start_url").String()
		} else if sec.HasKey("sso_start_url") {
			startURL = sec.Key("sso_start_url").String()
		}

		for _, pruneURL := range opts.PruneStartURLs {
			isGenerated := sec.HasKey("granted_generated_from") || sec.HasKey("common_fate_generated_from")

			if isGenerated && startURL == pruneURL {
				opts.Config.DeleteSection(sec.Name())
			}
		}
	}

	for _, ssoProfile := range opts.Profiles {
		ssoProfile.AccountName = normalizeAccountName(ssoProfile.AccountName)
		sectionNameBuffer := bytes.NewBufferString("")
		err := sectionNameTempl.Execute(sectionNameBuffer, ssoProfile)
		if err != nil {
			return err
		}
		profileName := opts.Prefix + sectionNameBuffer.String()
		sectionName := "profile " + profileName

		opts.Config.DeleteSection(sectionName)
		section, err := opts.Config.NewSection(sectionName)
		if err != nil {
			return err
		}

		entry := ssoProfile.ToIni(profileName, opts.NoCredentialProcess)
		err = section.ReflectFrom(entry)
		if err != nil {
			return err
		}
	}

	return nil
}

type credentialProcessProfile struct {
	SSOStartURL   string `ini:"granted_sso_start_url"`
	SSORegion     string `ini:"granted_sso_region"`
	SSOAccountID  string `ini:"granted_sso_account_id"`
	SSORoleName   string `ini:"granted_sso_role_name"`
	GeneratedFrom string `ini:"granted_generated_from"`
	CredProcess   string `ini:"credential_process"`
	Region        string `ini:"region,omitempty"`
}

type regularProfile struct {
	SSOStartURL   string `ini:"sso_start_url"`
	SSORegion     string `ini:"sso_region"`
	SSOAccountID  string `ini:"sso_account_id"`
	GeneratedFrom string `ini:"granted_generated_from"`
	SSORoleName   string `ini:"sso_role_name"`
	Region        string `ini:"region,omitempty"`
}

func normalizeAccountName(accountName string) string {
	return strings.ReplaceAll(accountName, " ", "-")
}
