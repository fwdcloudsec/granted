package prompt

import (
	"errors"
	"os"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// set max height to ensure longer outputs do no get cut off when displaying the selction
const maxFormHeight = 12

var NonEmpty = func(s string) error {
	if s == "" {
		return errors.New("response cannot be empty")
	}
	return nil
}

// Form wraps a single huh field in granted's theme. Output goes to stderr:
// stdout carries the GrantedAssume line the shell evals.
func Form(field huh.Field) *huh.Form {
	form := huh.NewForm(huh.NewGroup(field)).
		WithOutput(os.Stderr).
		WithTheme(theme{})

	// WithHeight pads a form out to the given height, so only tall fields get it
	if lipgloss.Height(field.View()) > maxFormHeight {
		form = form.WithHeight(maxFormHeight)
	}
	return form
}
