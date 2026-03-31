package cfregistry

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/cfcfg"
	awsv1alpha1 "github.com/common-fate/sdk/gen/granted/registry/aws/v1alpha1"
	"github.com/common-fate/sdk/gen/granted/registry/aws/v1alpha1/awsv1alpha1connect"
	"github.com/common-fate/sdk/loginflow"
	grantedv1alpha1 "github.com/common-fate/sdk/service/granted/registry"
	"gopkg.in/ini.v1"
)

type Registry struct {
	opts Opts
	mu   sync.Mutex
	// client is the profile registry service client.
	//
	// Do not use client directly. Instead, call
	// r.getClient() which will automatically populate it.
	client awsv1alpha1connect.ProfileRegistryServiceClient
}

type Opts struct {
	Name string
	URL  string
}

// getClient lazily loads the Profile Registry service client.
//
// Becuase the Registry is constructed every time the Granted CLI executes,
// calling `config.LoadDefault()` when creating the registry makes Granted very slow.
// Instead, we only obtain an OIDC token if we actually need to load profiles for the registry.
func (r *Registry) getClient(interactive bool) (awsv1alpha1connect.ProfileRegistryServiceClient, error) {
	// if the cached
	if r.client != nil {
		return r.client, nil
	}

	// Load the config from the deployment URL
	cfg, err := cfcfg.LoadURL(context.Background(), r.opts.URL)
	if err != nil {
		// NOTE(josh): ideally we'll bubble up a more strongly typed error in future here, to avoid the string comparison on the error message.
		// the OAuth2.0 token is expired so we should prompt the user to log in
		if needsToRefreshLogin(err) {
			if interactive {
				clio.Infof("You need to log into Common Fate to sync your profile registry")
				lf := loginflow.NewFromConfig(cfg)
				err = lf.Login(context.Background())
				if err != nil {
					return nil, err
				}
			} else {
				// in non interactive mode, just return a wrapped error
				return nil, fmt.Errorf("you need to log into Common Fate to sync your profile registry using `granted auth login`: %w", err)
			}

		} else {
			return nil, err
		}
	}

	accountClient := grantedv1alpha1.NewFromConfig(cfg)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.client = accountClient

	return r.client, nil
}
func needsToRefreshLogin(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "oauth2: token expired") {
		return true
	}
	if strings.Contains(err.Error(), "oauth2: invalid grant") {
		return true
	}
	// Sanity check that error message is matching correctly
	if strings.Contains(err.Error(), `oauth2: "token_expired"`) {
		return true
	}
	if strings.Contains(err.Error(), `oauth2: "invalid_grant"`) {
		return true
	}

	return false
}

func New(opts Opts) *Registry {
	r := Registry{
		opts: opts,
	}

	return &r
}

func (r *Registry) AWSProfiles(ctx context.Context, interactive bool) (*ini.File, error) {
	client, err := r.getClient(interactive)
	if err != nil {
		return nil, err
	}

	// call the Profile Registry API to pull the avilable profiles.
	done := false
	var pageToken string
	profiles := []*awsv1alpha1.Profile{}

	for !done {
		listProfiles, err := client.ListProfiles(ctx, &connect.Request[awsv1alpha1.ListProfilesRequest]{
			Msg: &awsv1alpha1.ListProfilesRequest{
				PageToken: pageToken,
			},
		})
		if err != nil {
			return nil, err
		}

		profiles = append(profiles, listProfiles.Msg.Profiles...)

		if listProfiles.Msg.NextPageToken == "" {
			done = true
		} else {
			pageToken = listProfiles.Msg.NextPageToken
		}
	}

	result := ini.Empty()

	for _, profile := range profiles {

		section, err := result.NewSection(profile.Name)
		if err != nil {
			return nil, err
		}

		//expect all the attributes to come from the api with the correct key value pairs
		for _, attr := range profile.Attributes {
			_, err := section.NewKey(attr.Key, attr.Value)
			if err != nil {
				return nil, err
			}

		}

	}

	return result, nil
}
