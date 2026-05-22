package testable

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"charm.land/huh/v2"
)

// Prompter is the interactive-prompt abstraction used by the testable
// package's top-level prompt functions. Implementations write to os.Stderr
// by default because granted's stdout is shell-evaluated.
type Prompter interface {
	Confirm(message string, defaultValue bool) (bool, error)
	Select(message string, options []string) (string, error)
}

var (
	defaultPrompter Prompter = newHuhPrompter()
	huhKeyMap       *huh.KeyMap
)

func init() {
	// huh v2's default Quit binding is ctrl+c only; extend it so ESC also
	// cancels the prompt, which matches what users expect from modal pickers.
	huhKeyMap = huh.NewDefaultKeyMap()
	huhKeyMap.Quit.SetKeys("ctrl+c", "esc")
	huhKeyMap.Quit.SetHelp("esc/ctrl+c", "cancel")
}

// Confirm shows a yes/no prompt. In testing mode it consumes one value
// from the input stream configured by WithNextSurveyInputFunc.
func Confirm(message string, defaultValue bool) (bool, error) {
	return defaultPrompter.Confirm(message, defaultValue)
}

// Select shows a single-choice list. In testing mode it consumes one value
// from the input stream configured by WithNextSurveyInputFunc.
func Select(message string, options []string) (string, error) {
	return defaultPrompter.Select(message, options)
}

type huhPrompter struct {
	stdin  io.Reader
	stdout io.Writer
}

func newHuhPrompter() *huhPrompter {
	return &huhPrompter{stdin: os.Stdin, stdout: os.Stderr}
}

func (h *huhPrompter) Confirm(message string, defaultValue bool) (bool, error) {
	if isTesting {
		return testInputAsBool()
	}
	ans := defaultValue
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().Title(message).Value(&ans),
		),
	).WithInput(h.stdin).WithOutput(h.stdout).WithKeyMap(huhKeyMap).Run()
	return ans, err
}

func (h *huhPrompter) Select(message string, options []string) (string, error) {
	if isTesting {
		return testInputAsString(), nil
	}
	var ans string
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title(message).
				Options(huh.NewOptions(options...)...).
				Value(&ans),
		),
	).WithInput(h.stdin).WithOutput(h.stdout).WithKeyMap(huhKeyMap).Run()
	return ans, err
}

func testInputAsString() string {
	v := nextSurveyInput()
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func testInputAsBool() (bool, error) {
	v := nextSurveyInput()
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		b, err := strconv.ParseBool(x)
		if err != nil {
			return false, fmt.Errorf("testable.Confirm: cannot parse %q as bool: %w", x, err)
		}
		return b, nil
	default:
		return false, fmt.Errorf("testable.Confirm: unexpected test input type %T", v)
	}
}
