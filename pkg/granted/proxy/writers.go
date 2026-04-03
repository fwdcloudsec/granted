package proxy

import (
	"strings"

	"github.com/common-fate/clio"
)

// DebugWriter is an io.Writer that writes messages using clio.Debug.
type DebugWriter struct{}

// Write implements the io.Writer interface for DebugWriter.
func (dw DebugWriter) Write(p []byte) (n int, err error) {
	message := string(p)
	clio.Debug(message)
	return len(p), nil
}

type NotifyOnSubstringMatchWriter struct {
	Phrase   string
	Callback func()
}

func (nw *NotifyOnSubstringMatchWriter) Write(p []byte) (n int, err error) {
	// Check if the phrase is in the input
	if strings.Contains(string(p), nw.Phrase) {
		go nw.Callback()
	}
	return len(p), nil
}
