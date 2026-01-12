//go:build windows
// +build windows

package chromemsg

import (
	"path/filepath"

	"github.com/fwdcloudsec/granted/pkg/config"
	"golang.org/x/sys/windows/registry"
)

// Configure writes native messaging host configuration to various well-known folders,
// including Google Chrome, Arc, Microsoft Edge, and Vivaldi.
//
// See: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host
//
// The resulting file looks like this:
//
//	  {
//		 "name": "io.commonfate.granted",
//		 "description": "Granted BrowserSupport",
//		 "path": "/usr/local/bin/granted",
//		 "type": "stdio",
//		 "allowed_origins": [
//		   "chrome-extension://fcipjekpmlpmiikgdecbjbcpmenmceoh/"
//		 ]
//	  }
func ConfigureHost() error {
	return configureWindows()
}

// configureWindows configures Windows registry entries pointing to the native messaging manifest file.
//
// From the Chrome developer documentation:
//
// "On Windows, the manifest file can be located anywhere in the file system.
// The application installer must create a registry key, either
// HKEY_LOCAL_MACHINE\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.my_company.my_application
// or HKEY_CURRENT_USER\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.my_company.my_application,
// and set the default value of that key to the full path to the manifest file.
func configureWindows() error {

	paths := []string{
		"Software\\Google\\Chrome\\NativeMessagingHosts",
		"Software\\Chromium\\NativeMessagingHosts",
	}

	grantedConfigFolder, err := config.GrantedConfigFolder()
	if err != nil {
		return err
	}

	manifestPath := filepath.Join(grantedConfigFolder, "native-messaging-host-manifest.json")
	err = writeManifest(manifestPath)
	if err != nil {
		return err
	}

	for _, regPath := range paths {
		key, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			continue
		}
		defer key.Close()

		gkey, _, err := registry.CreateKey(key, "io.commonfate.granted", registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			continue
		}
		defer gkey.Close()

		if err = gkey.SetStringValue("", manifestPath); err != nil {
			return err
		}
	}
	return nil
}
