package testable

import (
	"errors"
	"testing"
)

// The public Select functions have to actually reach the picker. They were once
// left pointing at a huh.Form while the picker sat unused: Go does not flag an
// uncalled method, and every other test here drives the picker model directly,
// so the whole suite passed with the feature disconnected. These go through the
// package-level entry points for that reason.
func TestSelectEntryPointsReachThePicker(t *testing.T) {
	type call struct {
		message     string
		options     []string
		hasValidate bool
	}

	withSpy := func(t *testing.T) *call {
		t.Helper()
		got := &call{}
		spy := newHuhPrompter()
		spy.runSelect = func(message string, options []string, validate func(string) error) (string, error) {
			got.message, got.options, got.hasValidate = message, options, validate != nil
			return "chosen", nil
		}
		orig := defaultPrompter
		t.Cleanup(func() { defaultPrompter = orig })
		defaultPrompter = spy
		return got
	}

	options := []string{"one", "two"}

	t.Run("Select", func(t *testing.T) {
		got := withSpy(t)
		answer, err := Select("pick one", options)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if answer != "chosen" {
			t.Errorf("answer = %q, want the picker's result", answer)
		}
		if got.message != "pick one" || len(got.options) != 2 {
			t.Errorf("picker called with (%q, %v), want the caller's arguments", got.message, got.options)
		}
		if got.hasValidate {
			t.Error("a validator was passed to a Select that has none")
		}
	})

	t.Run("SelectWithValidator", func(t *testing.T) {
		got := withSpy(t)
		if _, err := SelectWithValidator("pick one", options, func(string) error {
			return errors.New("nope")
		}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.hasValidate {
			t.Error("the validator did not reach the picker")
		}
	})
}
