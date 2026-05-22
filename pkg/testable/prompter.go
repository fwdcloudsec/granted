package testable

import (
	"errors"
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
	SelectWithValidator(message string, options []string, validate func(string) error) (string, error)
	Input(message string, defaultValue string) (string, error)
	InputWithValidator(message, defaultValue string, validate func(string) error) (string, error)
	Password(message string) (string, error)
}

// Required is a validator that rejects empty input.
var Required = func(s string) error {
	if s == "" {
		return errors.New("response cannot be empty")
	}
	return nil
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

// SelectWithValidator shows a single-choice list that re-prompts until the
// validator accepts the selection. In testing mode the validator is ignored
// and one value is consumed from the test input stream.
func SelectWithValidator(message string, options []string, validate func(string) error) (string, error) {
	return defaultPrompter.SelectWithValidator(message, options, validate)
}

// Input shows a free-form text prompt. In testing mode it consumes one value
// from the input stream configured by WithNextSurveyInputFunc.
func Input(message string, defaultValue string) (string, error) {
	return defaultPrompter.Input(message, defaultValue)
}

// InputWithValidator shows a free-form text prompt that re-prompts until the
// validator accepts the response. In testing mode the validator is ignored
// and one value is consumed from the test input stream.
func InputWithValidator(message, defaultValue string, validate func(string) error) (string, error) {
	return defaultPrompter.InputWithValidator(message, defaultValue, validate)
}

// Password shows a masked-input prompt. In testing mode it consumes one value
// from the input stream configured by WithNextSurveyInputFunc.
func Password(message string) (string, error) {
	return defaultPrompter.Password(message)
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
	return h.selectWith(message, options, nil)
}

func (h *huhPrompter) SelectWithValidator(message string, options []string, validate func(string) error) (string, error) {
	return h.selectWith(message, options, validate)
}

func (h *huhPrompter) selectWith(message string, options []string, validate func(string) error) (string, error) {
	if isTesting {
		return testInputAsString(), nil
	}
	var ans string
	sel := huh.NewSelect[string]().
		Title(message).
		Options(huh.NewOptions(options...)...).
		Value(&ans)
	if validate != nil {
		sel = sel.Validate(validate)
	}
	err := huh.NewForm(
		huh.NewGroup(sel),
	).WithInput(h.stdin).WithOutput(h.stdout).WithKeyMap(huhKeyMap).Run()
	return ans, err
}

func (h *huhPrompter) Input(message string, defaultValue string) (string, error) {
	return h.inputWith(message, defaultValue, nil)
}

func (h *huhPrompter) InputWithValidator(message, defaultValue string, validate func(string) error) (string, error) {
	return h.inputWith(message, defaultValue, validate)
}

func (h *huhPrompter) inputWith(message, defaultValue string, validate func(string) error) (string, error) {
	if isTesting {
		return testInputAsString(), nil
	}
	ans := defaultValue
	in := huh.NewInput().Title(message).Value(&ans)
	if validate != nil {
		in = in.Validate(validate)
	}
	err := huh.NewForm(
		huh.NewGroup(in),
	).WithInput(h.stdin).WithOutput(h.stdout).WithKeyMap(huhKeyMap).Run()
	return ans, err
}

func (h *huhPrompter) Password(message string) (string, error) {
	if isTesting {
		return testInputAsString(), nil
	}
	var ans string
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title(message).EchoMode(huh.EchoModePassword).Value(&ans),
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
