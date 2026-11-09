package autosync

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"time"

	"github.com/common-fate/clio"
)

const (
	FILENAME = "registry-sync"
)

type RegistrySyncConfig struct {
	dir              string
	LastCheckForSync time.Weekday `json:"lastCheckForSync"`
}

// return the absolute path of the registry-sync file.
func (rc RegistrySyncConfig) Path() string {
	return path.Join(rc.dir, FILENAME)
}

// create or save config in required file path.
func (rc RegistrySyncConfig) Save() error {
	if rc.dir == "" {
		return errors.New("version config dir was not specified")
	}

	err := os.MkdirAll(rc.dir, os.ModePerm)
	if err != nil {
		return err
	}

	data, err := json.Marshal(rc)
	if err != nil {
		return err
	}

	err = os.WriteFile(rc.Path(), data, 0666)
	if err != nil {
		return err
	}

	return nil
}

// if the required dir is present then os.MkdirAll will return nil
// therefore we will check if 'registry-sync' file is present or not
// if present then unmarshall the file and return the registry sync config
// else log and return
func loadRegistryConfig() (rc RegistrySyncConfig, ok bool) {
	cd, err := os.UserConfigDir()
	if err != nil {
		clio.Debug("error loading user config dir: %s", err.Error())
		return
	}

	rc.dir = path.Join(cd, "granted")
	err = os.MkdirAll(rc.dir, os.ModePerm)
	if err != nil {
		clio.Debug("error creating granted config dir: %s", err.Error())
		return
	}

	rcfile := path.Join(rc.dir, FILENAME)
	if _, err := os.Stat(rcfile); errors.Is(err, os.ErrNotExist) {
		clio.Debug("registry sync config file does not exist: %s", rcfile)
		return
	}

	data, err := os.ReadFile(rcfile)
	if err != nil {
		clio.Debug("error reading registry sync config: %s", err.Error())
		return
	}
	err = json.Unmarshal(data, &rc)
	if err != nil {
		clio.Debug("error unmarshalling registry sync config: %s", err.Error())
		return
	}
	ok = true
	return
}
