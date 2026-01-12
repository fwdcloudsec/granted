package gitregistry

import (
	"context"
	"path"

	"github.com/common-fate/clio"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"gopkg.in/ini.v1"
)

type Registry struct {
	opts Opts
	// clonedTo is the directory that the repo has been cloned to locally.
	clonedTo string
}

type Opts struct {
	Name         string
	URL          string
	Path         string
	Filename     string
	Ref          string
	RequiredKeys []string
	Interactive  bool
}

func New(opts Opts) (*Registry, error) {
	gConfigPath, err := grantedConfig.GrantedConfigFolder()
	if err != nil {
		return nil, err
	}

	clonedTo := path.Join(gConfigPath, "registries", opts.Name)

	p := Registry{
		opts:     opts,
		clonedTo: clonedTo,
	}

	return &p, nil
}

func (r Registry) AWSProfiles(ctx context.Context, interactive bool) (*ini.File, error) {
	err := r.pull()
	if err != nil {
		return nil, err
	}

	cfg, err := r.parseGrantedYAML()
	if err != nil {
		return nil, err
	}

	err = cfg.PromptRequiredKeys(r.opts.RequiredKeys, r.opts.Interactive, r.opts.Name)
	if err != nil {
		return nil, err
	}

	// load all cloned configs of a single repo into one ini object.
	// this will overwrite if there are duplicate profiles with same name.
	result := ini.Empty()

	for _, cfile := range cfg.AwsConfigPaths {
		var filepath string
		if r.opts.Path != "" {
			filepath = path.Join(r.clonedTo, r.opts.Path, cfile)
		} else {
			filepath = path.Join(r.clonedTo, cfile)
		}

		clio.Debugf("loading aws config file from %s", filepath)
		err := result.Append(filepath)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}
