package launcher

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/browser"
)

type ChromeProfile struct {
	// ExecutablePath is the path to the Chrome binary on the system.
	ExecutablePath string

	BrowserType string
}

func (l ChromeProfile) LaunchCommand(url string, profile string) ([]string, error) {
	// Chrome profiles can't contain slashes
	profileName := strings.ReplaceAll(profile, "/", "-")
	profileDir := findBrowserProfile(profileName, l.BrowserType)

	setProfileName(profileName, l.BrowserType)

	return []string{
		l.ExecutablePath,
		"--profile-directory=" + profileDir,
		"--no-first-run",
		"--no-default-browser-check",
		url,
	}, nil
}

var BravePathMac = "Library/Application Support/BraveSoftware/Brave-Browser/Local State"
var BravePathLinux = ".config/brave-browser/Local State"
var BravePathWindows = `AppData\Local\BraveSoftware\Brave-Browser\Local State`

var ChromePathMac = "Library/Application Support/Google/Chrome/Local State"
var ChromePathLinux = ".config/google-chrome/Local State"
var ChromePathWindows = `AppData\Local\Google\Chrome\User Data/Local State`

var EdgePathMac = `Library/Application Support/Microsoft\ Edge/Local State`
var EdgePathLinux = ".config/microsoft-edge/Local State"
var EdgePathWindows = `AppData\Local\Microsoft Edge\User Data/Local State`

var ChromiumPathMac = "Library/Application Support/Chromium/Local State"
var ChromiumPathLinux = ".config/chromium/Local State"
var ChromiumPathWindows = `AppData\Local\Chromium\User Data/Local State`

var VivaldiPathMac = "Library/Application Support/Vivaldi/Local State"
var VivaldiPathLinux = ".config/vivaldi/Local State"
var VivaldiPathWindows = `AppData\Local\Vivaldi\User Data/Local State`

// setProfileName attempts to rename an existing Chrome profile from 'Person 2', 'Person 3', etc
// into the name of the AWS profile that we're launching.
//
// The first time a particular profile is launched, this function will do nothing as the Chrome profile
// does not yet exist in the Local State file.
// However, subsequent launches will cause the profile to be correctly renamed.
func setProfileName(profile string, browserType string) {
	stateFile, err := getLocalStatePath(browserType)
	if err != nil {
		clio.Debugf("unable to find localstate path with err %s", err)
		return
	}

	// read the state file
	data, err := os.ReadFile(stateFile)
	if err != nil {
		clio.Debugf("unable to read local state file with err %s", err)
		return
	}

	// the Local State json blob is a bunch of map[string]interfaces which makes it difficult to unmarshal
	var f map[string]any
	err = json.Unmarshal(data, &f)
	if err != nil {
		clio.Debugf("unable to unmarshal local state file with err %s", err)
		return
	}

	// grab the profiles out from the json blob
	profiles, ok := f["profile"].(map[string]any)
	if !ok {
		clio.Debugf("could not cast profiles to map[string]any")
		return
	}

	infoCache, ok := profiles["info_cache"].(map[string]any)
	if !ok {
		clio.Debugf("could not cast info_cache to map[string]any")
		return
	}

	profileObj, ok := infoCache[profile]
	if !ok {
		clio.Debugf("could not find profile %s in info_cache", profile)
		return
	}

	profileContents, ok := profileObj.(map[string]any)
	if !ok {
		clio.Debugf("could not cast profile object to map[string]any")
		return
	}

	if profileContents["name"] != profile {
		clio.Debugf("updating profile name from %s to %s", profileContents["name"], profile)
		profileContents["name"] = profile
	}

	file, err := os.OpenFile(stateFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		clio.Debugf("could not open Local State file: %s", err)
		return
	}

	defer func() { _ = file.Close() }()
	encoder := json.NewEncoder(file)
	err = encoder.Encode(f)
	if err != nil {
		clio.Debugf("encode error to Local State file: %s", err)
		return
	}
}

func findBrowserProfile(profile string, browserType string) string {
	// open Local State file for browser
	// work out which chromium browser we are using
	stateFile, err := getLocalStatePath(browserType)
	if err != nil {
		clio.Debugf("unable to find localstate path with err %s", err)
		return profile
	}

	// read the state file
	data, err := os.ReadFile(stateFile)
	if err != nil {
		clio.Debugf("unable to read local state file with err %s", err)
		return profile
	}

	// the Local State json blob is a bunch of map[string]interfaces which makes it difficult to unmarshal
	var f map[string]any
	err = json.Unmarshal(data, &f)
	if err != nil {
		clio.Debugf("unable to unmarshal local state file with err %s", err)
		return profile
	}

	// grab the profiles out from the json blob
	profiles, ok := f["profile"].(map[string]any)
	if !ok {
		clio.Debugf("could not cast profiles to map[string]any")
		return profile
	}

	infoCache, ok := profiles["info_cache"].(map[string]any)
	if !ok {
		clio.Debugf("could not cast info_cache to map[string]any")
		return profile
	}

	for chromeProfileID, profileObj := range infoCache {
		profileContents, ok := profileObj.(map[string]any)
		if !ok {
			continue
		}

		// if the name field from the Chrome profile is the same as the provided profile name, return the ID of the Chrome profile.
		if profileContents["name"] == profile {
			return chromeProfileID
		}

	}

	// otherwise, fall back to returning the input profile name.
	return profile
}

func getLocalStatePath(browserType string) (stateFile string, err error) {
	stateFile, err = os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "windows":
		switch browserType {
		case browser.ChromeKey:
			stateFile = path.Join(stateFile, ChromePathWindows)

		case browser.BraveKey:
			stateFile = path.Join(stateFile, BravePathWindows)

		case browser.EdgeKey:
			stateFile = path.Join(stateFile, EdgePathWindows)

		case browser.ChromiumKey:
			stateFile = path.Join(stateFile, ChromiumPathWindows)

		case browser.VivaldiKey:
			stateFile = path.Join(stateFile, VivaldiPathWindows)
		}

	case "darwin":
		switch browserType {
		case browser.ChromeKey:
			stateFile = path.Join(stateFile, ChromePathMac)

		case browser.BraveKey:
			stateFile = path.Join(stateFile, BravePathMac)

		case browser.EdgeKey:
			stateFile = path.Join(stateFile, EdgePathMac)

		case browser.ChromiumKey:
			stateFile = path.Join(stateFile, ChromiumPathMac)

		case browser.VivaldiKey:
			stateFile = path.Join(stateFile, VivaldiPathMac)
		}

	case "linux":
		switch browserType {
		case browser.ChromeKey:
			stateFile = path.Join(stateFile, ChromePathLinux)

		case browser.BraveKey:
			stateFile = path.Join(stateFile, BravePathLinux)

		case browser.EdgeKey:
			stateFile = path.Join(stateFile, EdgePathLinux)

		case browser.ChromiumKey:
			stateFile = path.Join(stateFile, ChromiumPathLinux)

		case browser.VivaldiKey:
			stateFile = path.Join(stateFile, VivaldiPathLinux)
		}

	default:
		clio.Debug("getting local state path: os not supported")
		return "", errors.New("os not supported")
	}
	return stateFile, nil
}

func (l ChromeProfile) UseForkProcess() bool { return true }
