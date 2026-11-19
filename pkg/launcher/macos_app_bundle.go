package launcher

import (
	"runtime"
	"strings"
)

// hostOS is a variable so that tests can cover the macOS behaviour on any platform.
var hostOS = runtime.GOOS

// macOSAppBundle returns the .app bundle that contains executablePath, such as
// /Applications/Firefox.app for /Applications/Firefox.app/Contents/MacOS/firefox,
// or "" when not on macOS or the executable is not inside an app bundle.
//
// Launchers open the bundle with 'open -a' instead of running the executable.
// When a terminal runs the executable, macOS treats the terminal as the
// responsible process, and App Data protection then stops the browser from
// reading its own profile directory. Firefox reports this as "Profile Missing".
func macOSAppBundle(executablePath string) string {
	if hostOS != "darwin" {
		return ""
	}
	bundleEnd := strings.Index(executablePath, ".app/Contents/MacOS/")
	if bundleEnd == -1 {
		return ""
	}
	return executablePath[:bundleEnd+len(".app")]
}
