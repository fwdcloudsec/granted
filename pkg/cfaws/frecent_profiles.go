package cfaws

import (
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/frecency"
	"github.com/pkg/errors"
)

var frecencyStoreKey = "aws_profiles_frecency"

type FrecentProfiles struct {
	store    *frecency.FrecencyStore
	toRemove []string
}

// should be called after selecting a profile to update frecency cache
// wrap this method in a go routine to avoid blocking the user
func (f *FrecentProfiles) Update(selectedProfile string) {
	s := make([]interface{}, len(f.toRemove))
	for i, v := range f.toRemove {
		s[i] = v
	}
	err := f.store.DeleteAll(s)
	if err != nil {
		clio.Debug(errors.Wrap(err, "removing entries from frecency").Error())
	}
	err = f.store.Upsert(selectedProfile)
	if err != nil {
		clio.Debug(errors.Wrap(err, "upserting entry to frecency").Error())
	}
}

// use this to update frecency cache when the profile is supplied by the commandline
func UpdateFrecencyCache(selectedProfile string) {
	fr, err := frecency.Load(frecencyStoreKey)
	if err != nil {
		clio.Debug(errors.Wrap(err, "loading aws_profiles_frecency frecency store").Error())
	} else {
		err = fr.Upsert(selectedProfile)
		if err != nil {
			clio.Debug(errors.Wrap(err, "upserting entry to frecency").Error())
		}
	}
}

// loads the frecency cache and generates a list of profiles with frecently used profiles first, followed by alphabetically sorted profiles that have not been used with assume
// this method returns a FrecentProfiles pointer which should be used after selecting a profile to update the cache, it will also remove any entries which no longer exist in the aws config
func (p *Profiles) GetFrecentProfiles() (*FrecentProfiles, []string) {
	names := []string{}
	namesMap := make(map[string]string)
	fr, err := frecency.Load(frecencyStoreKey)
	if err != nil {
		clio.Debug(errors.Wrap(err, "loading aws_profiles_frecency frecency store").Error())
	}
	namesToRemoveFromFrecency := []string{}

	// add all frecent profile names in order if they are still present in the profileNames slice
	for _, entry := range fr.Entries {
		e, ok := entry.Entry.(string)
		if !ok {
			continue
		}

		if p.HasProfile(e) {
			names = append(names, e)
			namesMap[e] = e
		} else {
			namesToRemoveFromFrecency = append(namesToRemoveFromFrecency, e)
		}
	}

	// add all other entries from profileNames, sort them alphabetically first
	for _, n := range p.ProfileNames {
		if _, ok := namesMap[n]; !ok {
			names = append(names, n)
		}
	}
	frPr := &FrecentProfiles{store: fr, toRemove: namesToRemoveFromFrecency}

	return frPr, names
}
