package awsconfigfile

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"gopkg.in/ini.v1"
)

// Source returns AWS profiles to be combined into an AWS config file.
type Source interface {
	GetProfiles(ctx context.Context) ([]SSOProfile, error)
}

// Generator generates AWS profiles for ~/.aws/config.
// It reads profiles from sources and merges them with
// an existing ini config file.
type Generator struct {
	Sources             []Source
	Config              *ini.File
	NoCredentialProcess bool
	ProfileNameTemplate string
	Prefix              string
	// PruneStartURLs is a slice of AWS SSO start URLs which profiles are being
	// generated for. Existing profiles with these start URLs will be removed if
	// they aren't found in the Profiles field.
	PruneStartURLs []string
}

// AddSource adds a new source to load profiles from to the generator.
func (g *Generator) AddSource(source Source) {
	g.Sources = append(g.Sources, source)
}

const profileSectionIllegalChars = ` \][;'"`

// regular expression that matches on the characters \][;'" including whitespace,
// but does not match anything between {{ }} so it does not check inside go templates
var profileSectionIllegalCharsRegex = regexp.MustCompile(`(?s)((?:^|[^\{])[\s\][;'"]|[\][;'"][\s]*(?:$|[^\}]))`)
var matchGoTemplateSection = regexp.MustCompile(`\{\{[\s\S]*?\}\}`)

var DefaultProfileNameTemplate = "{{ .AccountName }}/{{ .RoleName }}"

// Generate AWS profiles and merge them with the existing config.
func (g *Generator) Generate(ctx context.Context) error {
	var eg errgroup.Group
	var mu sync.Mutex
	var profiles []SSOProfile

	if strings.ContainsAny(g.Prefix, profileSectionIllegalChars) {
		return fmt.Errorf("profile prefix must not contain any of these illegal characters (%s)", profileSectionIllegalChars)
	}

	if g.ProfileNameTemplate == "" {
		g.ProfileNameTemplate = DefaultProfileNameTemplate
	}

	if g.ProfileNameTemplate != DefaultProfileNameTemplate {
		cleaned := matchGoTemplateSection.ReplaceAllString(g.ProfileNameTemplate, "")
		if profileSectionIllegalCharsRegex.MatchString(cleaned) {
			return fmt.Errorf("profile template must not contain any of these illegal characters (%s)", profileSectionIllegalChars)
		}
	}

	for _, s := range g.Sources {
		scopy := s
		eg.Go(func() error {
			got, err := scopy.GetProfiles(ctx)
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			profiles = append(profiles, got...)
			return nil
		})
	}

	err := eg.Wait()
	if err != nil {
		return err
	}

	err = Merge(MergeOpts{
		Config:              g.Config,
		SectionNameTemplate: g.ProfileNameTemplate,
		Profiles:            profiles,
		NoCredentialProcess: g.NoCredentialProcess,
		Prefix:              g.Prefix,
		PruneStartURLs:      g.PruneStartURLs,
	})
	return err
}
