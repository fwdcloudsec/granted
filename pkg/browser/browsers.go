package browser

import (
	"errors"
	"os/exec"
	"runtime"
)

// A browser supported by Granted.
const (
	ChromeKey            string = "CHROME"
	BraveKey             string = "BRAVE"
	EdgeKey              string = "EDGE"
	FirefoxKey           string = "FIREFOX"
	WaterfoxKey          string = "WATERFOX"
	ChromiumKey          string = "CHROMIUM"
	SafariKey            string = "SAFARI"
	StdoutKey            string = "STDOUT"
	FirefoxStdoutKey     string = "FIREFOX_STDOUT"
	ArcKey               string = "ARC"
	ZenKey               string = "ZEN"
	FirefoxDevEditionKey string = "FIREFOX_DEV"
	FirefoxNightlyKey    string = "FIREFOX_NIGHTLY"
	CustomKey            string = "CUSTOM"
	VivaldiKey           string = "VIVALDI"
)

// A few default paths to check for the browser
var ChromePathMac = []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
var ChromePathLinux = []string{`/usr/bin/google-chrome`, `/../../mnt/c/Program Files/Google/Chrome/Application/chrome.exe`, `/../../mnt/c/Program Files (x86)/Google/Chrome/Application/chrome.exe`}
var ChromePathWindows = []string{`\Program Files\Google\Chrome\Application\chrome.exe`, `\Program Files (x86)\Google\Chrome\Application\chrome.exe`}

var BravePathMac = []string{"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"}
var BravePathLinux = []string{`/usr/bin/brave-browser`, `/../../mnt/c/Program Files/BraveSoftware/Brave-Browser/Application/brave.exe`}
var BravePathWindows = []string{`\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`}

var EdgePathMac = []string{"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"}
var EdgePathLinux = []string{`/usr/bin/edge`, `/../../mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe`}
var EdgePathWindows = []string{`\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`}

var FirefoxPathMac = []string{"/Applications/Firefox.app/Contents/MacOS/firefox"}
var FirefoxPathLinux = []string{`/usr/bin/firefox`, `/../../mnt/c/Program Files/Mozilla Firefox/firefox.exe`}
var FirefoxPathWindows = []string{`\Program Files\Mozilla Firefox\firefox.exe`}

var FirefoxDevPathMac = []string{"/Applications/Firefox Developer Edition.app/Contents/MacOS/firefox"}
var FirefoxDevPathLinux = []string{`/usr/bin/firefox-developer`, `/../../mnt/c/Program Files/Firefox Developer Edition/firefox.exe`}
var FirefoxDevPathWindows = []string{`\Program Files\Firefox Developer Edition\firefox.exe`}

var FirefoxNightlyPathMac = []string{"/Applications/Firefox Nightly.app/Contents/MacOS/firefox"}
var FirefoxNightlyPathLinux = []string{`/usr/bin/firefox-nightly`, `/../../mnt/c/Program Files/Firefox Nightly/firefox.exe`}
var FirefoxNightlyPathWindows = []string{`\Program Files\Firefox Nightly\firefox.exe`}

var WaterfoxPathMac = []string{"/Applications/Waterfox.app/Contents/MacOS/waterfox"}
var WaterfoxPathLinux = []string{`/usr/bin/waterfox`, `/../../mnt/c/Program Files/Waterfox/waterfox.exe`}
var WaterfoxPathWindows = []string{`\Program Files\Waterfox\waterfox.exe`}

var ChromiumPathMac = []string{"/Applications/Chromium.app/Contents/MacOS/Chromium"}
var ChromiumPathLinux = []string{`/usr/bin/chromium`, `/../../mnt/c/Program Files/Chromium/chromium.exe`}
var ChromiumPathWindows = []string{`\Program Files\Chromium\chromium.exe`}

var VivaldiPathMac = []string{"/Applications/Vivaldi.app/Contents/MacOS/Vivaldi"}
var VivaldiPathLinux = []string{`/usr/bin/vivaldi`, `/../../mnt/c/Program Files/Vivaldi/Application/vivaldi.exe`}
var VivaldiPathWindows = []string{`\Program Files\Vivaldi\Application\vivaldi.exe`}

var SafariPathMac = []string{"/Applications/Safari.app/Contents/MacOS/Safari"}

var ArcPathMac = []string{"/Applications/Arc.app/Contents/MacOS/Arc"}

var ZenPathMac = []string{"/Applications/Zen Browser.app/Contents/MacOS/zen"}
var ZenPathLinux = []string{`/usr/bin/zen-browser`, `/opt/zen-browser/zen`}
var ZenPathWindows = []string{`\Program Files\Zen Browser\zen.exe`}

func ChromePathDefaults() ([]string, error) {
	// check linuxpath for binary install
	path, err := exec.LookPath("google-chrome-stable")
	if err != nil {
		path, err = exec.LookPath("google-chrome")
		if err == nil {
			return []string{path}, nil
		}
	}
	if err == nil {
		return []string{path}, nil
	}
	switch runtime.GOOS {
	case "windows":
		return ChromePathWindows, nil
	case "darwin":
		return ChromePathMac, nil
	case "linux":
		return ChromePathLinux, nil
	default:
		return nil, errors.New("os not supported")
	}
}

func BravePathDefaults() ([]string, error) {
	// check linuxpath for binary install
	path, err := exec.LookPath("brave")
	if err == nil {
		return []string{path}, nil
	}
	switch runtime.GOOS {
	case "windows":
		return BravePathWindows, nil
	case "darwin":
		return BravePathMac, nil
	case "linux":
		return BravePathLinux, nil
	default:
		return nil, errors.New("os not supported")
	}
}

func EdgePathDefaults() ([]string, error) {
	// check linuxpath for binary install
	path, err := exec.LookPath("edge")
	if err == nil {
		return []string{path}, nil
	}
	switch runtime.GOOS {
	case "windows":
		return EdgePathWindows, nil
	case "darwin":
		return EdgePathMac, nil
	case "linux":
		return EdgePathLinux, nil
	default:
		return nil, errors.New("os not supported")
	}
}

func FirefoxPathDefaults() ([]string, error) {
	// check linuxpath for binary install
	path, err := exec.LookPath("firefox")
	if err == nil {
		return []string{path}, nil
	}
	switch runtime.GOOS {
	case "windows":
		return FirefoxPathWindows, nil
	case "darwin":
		return FirefoxPathMac, nil
	case "linux":
		return FirefoxPathLinux, nil
	default:
		return nil, errors.New("os not supported")
	}
}

func FirefoxDevPathDefaults() ([]string, error) {
	// check linuxpath for binary install
	path, err := exec.LookPath("firefox-developer")
	if err == nil {
		return []string{path}, nil
	}
	switch runtime.GOOS {
	case "windows":
		return FirefoxDevPathWindows, nil
	case "darwin":
		return FirefoxDevPathMac, nil
	case "linux":
		return FirefoxDevPathLinux, nil
	default:
		return nil, errors.New("os not supported")
	}
}

func FirefoxNightlyPathDefaults() ([]string, error) {
	// check linuxpath for binary install
	path, err := exec.LookPath("firefox-nightly")
	if err == nil {
		return []string{path}, nil
	}
	switch runtime.GOOS {
	case "windows":
		return FirefoxNightlyPathWindows, nil
	case "darwin":
		return FirefoxNightlyPathMac, nil
	case "linux":
		return FirefoxNightlyPathLinux, nil
	default:
		return nil, errors.New("os not supported")
	}
}

func WaterfoxPathDefaults() ([]string, error) {
	// check linuxpath for binary install
	path, err := exec.LookPath("waterfox")
	if err == nil {
		return []string{path}, nil
	}
	switch runtime.GOOS {
	case "windows":
		return WaterfoxPathWindows, nil
	case "darwin":
		return WaterfoxPathMac, nil
	case "linux":
		return WaterfoxPathLinux, nil
	default:
		return nil, errors.New("os not supported")
	}
}

func ChromiumPathDefaults() ([]string, error) {
	// check linuxpath for binary install
	path, err := exec.LookPath("chromium")
	if err == nil {
		return []string{path}, nil
	}
	switch runtime.GOOS {
	case "windows":
		return ChromiumPathWindows, nil
	case "darwin":
		return ChromiumPathMac, nil
	case "linux":
		return ChromiumPathLinux, nil
	default:
		return nil, errors.New("os not supported")
	}
}

func VivaldiPathDefaults() ([]string, error) {
	// check linuxpath for binary install
	path, err := exec.LookPath("vivaldi")
	if err == nil {
		return []string{path}, nil
	}
	switch runtime.GOOS {
	case "windows":
		return VivaldiPathWindows, nil
	case "darwin":
		return VivaldiPathMac, nil
	case "linux":
		return VivaldiPathLinux, nil
	default:
		return nil, errors.New("os not supported")
	}
}

func SafariPathDefaults() ([]string, error) {
	switch runtime.GOOS {
	case "darwin":
		return SafariPathMac, nil
	default:
		return nil, errors.New("os not supported")
	}
}

func ArcPathDefaults() ([]string, error) {
	switch runtime.GOOS {
	case "darwin":
		return ArcPathMac, nil
	default:
		return nil, errors.New("os not supported")
	}
}

func ZenPathDefaults() ([]string, error) {
	path, err := exec.LookPath("zen-browser")
	if err == nil {
		return []string{path}, nil
	}
	switch runtime.GOOS {
	case "windows":
		return ZenPathWindows, nil
	case "darwin":
		return ZenPathMac, nil
	case "linux":
		return ZenPathLinux, nil
	default:
		return nil, errors.New("os not supported")
	}
}
