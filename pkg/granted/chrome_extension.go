package granted

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/fwdcloudsec/granted/internal/build"
	"github.com/fwdcloudsec/granted/pkg/chromemsg"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"github.com/urfave/cli/v2"
)

func HandleChromeExtensionCall(c *cli.Context) error {
	arg := c.Args().First()

	// When called with a chrome extension, the first argument will be the extension ID,
	// in a format like 'chrome-extension://fcipjekpmlpmiikgdecbjbcpmenmceoh'.
	//
	// We need to verify the extension ID matches our list of allowed Chrome extension IDs.

	u, err := url.Parse(arg)
	if err != nil {
		return fmt.Errorf("invalid Chrome Extension URL %q: %w", arg, err)
	}

	if u.Host != build.ChromeExtensionID {
		return fmt.Errorf("chrome Extension ID %q did not match allowed ID %q", u.Host, build.ChromeExtensionID)
	}

	// If we get here, the Granted CLI has been invoked from our browser extension.
	//
	// The browser extension native messaging protocol uses stdin and stdout to
	// communicate with the Granted CLI.
	//
	// See: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
	s := chromemsg.Server{
		Input:  os.Stdin,
		Output: os.Stdout,
	}

	var msg chromeMessage

	// Unmarshal the message received from the browser.
	err = json.NewDecoder(&s).Decode(&msg)
	if err != nil {
		return err
	}

	// Currently, the only valid message type is 'get_valid_user_codes'.
	// In future, we may introduce additional message types.
	if msg.Type != "get_valid_user_codes" {
		return fmt.Errorf("invalid type field: %s", msg.Type)
	}

	storage := securestorage.NewDeviceCodeSecureStorage()
	codes, err := storage.GetValidUserCodes()
	if err != nil {
		return err
	}

	err = json.NewEncoder(&s).Encode(codes)
	if err != nil {
		return err
	}

	// ensure stdout is flushed. If this isn't called, the
	// browser extension seems to have issues receiving data.
	return os.Stdout.Sync()
}

type chromeMessage struct {
	Type string `json:"type"`
}
