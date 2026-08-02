package testable

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// stubs the terminal size so assertions do not depend on the suite's terminal
func withTerminalHeight(t *testing.T, h int, isTerm bool) {
	t.Helper()
	orig := terminalHeight
	t.Cleanup(func() { terminalHeight = orig })
	terminalHeight = func() (int, bool) { return h, isTerm }
}

func numberedOptions(n int) []string {
	opts := make([]string, n)
	for i := range opts {
		opts[i] = fmt.Sprintf("Setting.Number%02d", i)
	}
	return opts
}

func typedKey(r rune) tea.Key { return tea.Key{Code: r, Text: string(r)} }

func typedKeys(s string) []tea.Key {
	keys := make([]tea.Key, 0, len(s))
	for _, r := range s {
		keys = append(keys, typedKey(r))
	}
	return keys
}

// drivePicker feeds keys to the production model, rendering between each one.
// huh.Select sets its viewport content during View, so scrolling needs frames.
func drivePicker(t *testing.T, options []string, termHeight int, validate func(string) error, keys ...tea.Key) selectPickerModel {
	t.Helper()
	m := newSelectPickerModel("Select the configuration to change", options, validate)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: termHeight})
	m = next.(selectPickerModel)
	_ = m.View()
	for _, k := range keys {
		next, _ = m.Update(tea.KeyPressMsg(k))
		m = next.(selectPickerModel)
		_ = m.View()
	}
	return m
}

func visibleOptions(view string, options []string) []string {
	var out []string
	for _, o := range options {
		if strings.Contains(view, o) {
			out = append(out, o)
		}
	}
	return out
}

// Typing filters directly, with no "/" first, as survey did.
func TestTypingFiltersWithoutAPrefixKey(t *testing.T) {
	withTerminalHeight(t, 30, true)
	options := []string{"prod-eu", "prod-us", "staging-eu", "dev-eu"}

	m := drivePicker(t, options, 30, nil, typedKeys("prod")...)

	if m.filter != "prod" {
		t.Errorf("filter = %q, want %q", m.filter, "prod")
	}
	if got := m.matches(); len(got) != 2 {
		t.Errorf("matches = %v, want the two prod profiles", got)
	}
}

// The title must not dress the filter up as a "/" mode, since no such prefix
// key exists and users copy what the prompt shows them.
func TestFilterIsNotShownAsASlashMode(t *testing.T) {
	withTerminalHeight(t, 30, true)

	m := drivePicker(t, numberedOptions(22), 30, nil, typedKeys("Number1")...)
	titleRow := stripStyles(strings.SplitN(m.View().Content, "\n", 2)[0])

	if strings.Contains(titleRow, "/Number1") {
		t.Errorf("title renders the filter as a slash mode: %q", titleRow)
	}
	if !strings.Contains(titleRow, "Number1") {
		t.Errorf("title does not show the active filter at all: %q", titleRow)
	}
	if !strings.Contains(titleRow, "Select the configuration to change") {
		t.Errorf("title dropped the message while filtering: %q", titleRow)
	}
}

func stripStyles(s string) string {
	var b strings.Builder
	inEscape := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			inEscape = true
		case inEscape && (r == 'm' || r == 'K'):
			inEscape = false
		case !inEscape:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// huh binds j/k and g/G by default; those letters must reach the filter instead.
func TestLettersFilterRatherThanNavigate(t *testing.T) {
	withTerminalHeight(t, 30, true)
	options := []string{"gjk-one", "other-two", "gjk-three"}

	m := drivePicker(t, options, 30, nil, typedKeys("gjk")...)

	if m.filter != "gjk" {
		t.Errorf("filter = %q, want %q: a letter was treated as navigation", m.filter, "gjk")
	}
	if got := len(m.matches()); got != 2 {
		t.Errorf("matches = %d, want 2", got)
	}
}

// Every match must be visible however the cursor moved first: huh leaves the
// viewport scrolled past earlier matches (charmbracelet/huh#669).
func TestFilteringShowsEveryMatchAfterScrolling(t *testing.T) {
	const termHeight = 20
	withTerminalHeight(t, termHeight, true)

	options := numberedOptions(22)
	var wanted []string
	for _, i := range []int{2, 9, 15, 20} {
		options[i] = fmt.Sprintf("Setting.def%02d", i)
		wanted = append(wanted, options[i])
	}

	for _, downs := range []int{0, 8, 15, 21} {
		keys := make([]tea.Key, 0, downs+3)
		for range downs {
			keys = append(keys, tea.Key{Code: tea.KeyDown})
		}
		keys = append(keys, typedKeys("def")...)

		view := drivePicker(t, options, termHeight, nil, keys...).View().Content
		if got := visibleOptions(view, wanted); len(got) != len(wanted) {
			t.Errorf("cursor moved down %d before filtering: %d of %d matches visible (%v)",
				downs, len(got), len(wanted), got)
		}
	}
}

// The window slides with the cursor rather than flipping pages.
func TestNavigationSlidesTheWindow(t *testing.T) {
	const termHeight = 30
	withTerminalHeight(t, termHeight, true)
	options := numberedOptions(22)

	windows := make([]string, 0, 3)
	for _, downs := range []int{0, 12, 21} {
		keys := make([]tea.Key, 0, downs)
		for range downs {
			keys = append(keys, tea.Key{Code: tea.KeyDown})
		}
		vis := visibleOptions(drivePicker(t, options, termHeight, nil, keys...).View().Content, options)
		if len(vis) == 0 {
			t.Fatalf("downs=%d: nothing visible", downs)
		}
		windows = append(windows, vis[0]+".."+vis[len(vis)-1])
	}
	if windows[0] == windows[1] && windows[1] == windows[2] {
		t.Errorf("window never moved across the list: %v", windows)
	}
	if windows[1] == windows[2] {
		t.Errorf("window did not follow the cursor to the end: %v", windows)
	}
}

// ESC drops an active filter first, and only cancels once there is none.
func TestEscClearsFilterBeforeCancelling(t *testing.T) {
	withTerminalHeight(t, 30, true)
	options := numberedOptions(22)
	esc := tea.Key{Code: tea.KeyEscape}

	t.Run("first esc drops the filter", func(t *testing.T) {
		m := drivePicker(t, options, 30, nil, append(typedKeys("Number1"), esc)...)
		if m.quitting {
			t.Fatal("esc cancelled instead of dropping the filter")
		}
		if m.filter != "" {
			t.Errorf("filter = %q, want it cleared", m.filter)
		}
		if got := len(m.matches()); got != len(options) {
			t.Errorf("matches = %d, want the full list of %d back", got, len(options))
		}
	})

	t.Run("second esc cancels", func(t *testing.T) {
		if m := drivePicker(t, options, 30, nil, append(typedKeys("Number1"), esc, esc)...); !m.quitting {
			t.Error("esc did not cancel once the filter was gone")
		}
	})

	t.Run("esc with no filter cancels immediately", func(t *testing.T) {
		if m := drivePicker(t, options, 30, nil, esc); !m.quitting {
			t.Error("esc did not cancel an unfiltered picker")
		}
	})
}

func TestCtrlCAlwaysCancels(t *testing.T) {
	withTerminalHeight(t, 30, true)
	ctrlC := tea.Key{Code: 'c', Mod: tea.ModCtrl}

	for name, keys := range map[string][]tea.Key{
		"idle":            {ctrlC},
		"while filtering": append(typedKeys("Number1"), ctrlC),
	} {
		t.Run(name, func(t *testing.T) {
			if !drivePicker(t, numberedOptions(22), 30, nil, keys...).quitting {
				t.Error("ctrl+c did not cancel")
			}
		})
	}
}

func TestBackspaceEditsFilter(t *testing.T) {
	withTerminalHeight(t, 30, true)
	back := tea.Key{Code: tea.KeyBackspace}

	m := drivePicker(t, numberedOptions(22), 30, nil, append(typedKeys("Number1"), back)...)
	if m.filter != "Number" {
		t.Errorf("filter = %q, want %q", m.filter, "Number")
	}
	if m := drivePicker(t, numberedOptions(22), 30, nil, back); m.quitting {
		t.Error("backspace on an empty filter cancelled the picker")
	}
}

// A rejected selection leaves the prompt open; the caller cannot reopen it.
func TestValidatorKeepsPromptOpen(t *testing.T) {
	withTerminalHeight(t, 30, true)
	options := numberedOptions(5)
	enter := tea.Key{Code: tea.KeyEnter}
	rejectFirst := func(s string) error {
		if s == "Setting.Number00" {
			return errors.New("that profile cannot be imported")
		}
		return nil
	}

	t.Run("rejected choice reports why and stays open", func(t *testing.T) {
		m := drivePicker(t, options, 30, rejectFirst, enter)
		if m.chosen {
			t.Errorf("choice = %q, want none: the selection was rejected", m.choice)
		}
		if m.quitting {
			t.Error("picker closed on a rejected selection")
		}
		if !strings.Contains(m.View().Content, "cannot be imported") {
			t.Error("the validator's reason is not shown to the user")
		}
	})

	t.Run("moving on clears the error and a valid choice is accepted", func(t *testing.T) {
		m := drivePicker(t, options, 30, rejectFirst, enter, tea.Key{Code: tea.KeyDown}, enter)
		if m.choice != "Setting.Number01" {
			t.Errorf("choice = %q, want %q", m.choice, "Setting.Number01")
		}
		if m.err != nil {
			t.Errorf("error %v survived a successful selection", m.err)
		}
	})

	t.Run("no validator accepts anything", func(t *testing.T) {
		if got := drivePicker(t, options, 30, nil, enter).choice; got != "Setting.Number00" {
			t.Errorf("choice = %q, want %q", got, "Setting.Number00")
		}
	})
}

// Enter must not select anything when the filter excludes every option.
func TestEnterWithNoMatchesDoesNothing(t *testing.T) {
	withTerminalHeight(t, 30, true)
	m := drivePicker(t, numberedOptions(5), 30, nil,
		append(typedKeys("zzz"), tea.Key{Code: tea.KeyEnter})...)

	if m.chosen {
		t.Errorf("choice = %q, want none when nothing matches", m.choice)
	}
	if m.quitting {
		t.Error("picker cancelled itself when nothing matched")
	}
}

// Rendering taller than the terminal scrolls away whatever was printed before
// the prompt, such as the registry commands' warnings.
func TestPickerFitsTerminal(t *testing.T) {
	const termHeight = 20
	withTerminalHeight(t, termHeight, true)

	for _, optionCount := range []int{1, 3, 10, 22, 60} {
		got := lipgloss.Height(drivePicker(t, numberedOptions(optionCount), termHeight, nil).View().Content)
		if got > termHeight {
			t.Errorf("%d options: picker rendered %d lines in a %d-line terminal",
				optionCount, got, termHeight)
		}
	}
}

// The height may only shrink a picker: a fixed one would pad short prompts.
func TestPickerHeightNeverGrows(t *testing.T) {
	withTerminalHeight(t, 40, true)

	for _, optionCount := range []int{1, 2, 3, 5, 10} {
		natural := optionCount + titleRow
		if got := pickerHeight(optionCount); got != natural {
			t.Errorf("%d options: height %d, want %d (its natural height, uncapped)",
				optionCount, got, natural)
		}
	}
	if got := pickerHeight(60); got != maxPickerOptions+titleRow {
		t.Errorf("60 options: height %d, want it capped at %d", got, maxPickerOptions+titleRow)
	}
}

func TestPickerHeightFitsSmallTerminals(t *testing.T) {
	t.Run("leaves room for preceding output", func(t *testing.T) {
		withTerminalHeight(t, 8, true)
		if got := pickerHeight(60); got != 6 {
			t.Errorf("height %d in an 8-line terminal, want 6 (terminal less 2)", got)
		}
	})

	t.Run("keeps room for one option in a tiny terminal", func(t *testing.T) {
		withTerminalHeight(t, 2, true)
		if got := pickerHeight(60); got != titleRow+1 {
			t.Errorf("height %d in a 2-line terminal, want %d", got, titleRow+1)
		}
	})

	t.Run("caps by option count when stderr is not a terminal", func(t *testing.T) {
		withTerminalHeight(t, 0, false)
		if got := pickerHeight(60); got != maxPickerOptions+titleRow {
			t.Errorf("height %d with no terminal, want %d", got, maxPickerOptions+titleRow)
		}
	})
}

// Every token must match, so fragments can be given in any order.
func TestDefaultFilter(t *testing.T) {
	for _, tc := range []struct {
		typed, option string
		want          bool
	}{
		{"", "eu-west-prod", true},
		{"prod", "eu-west-prod", true},
		{"PROD", "eu-west-prod", true},
		{"prod eu", "eu-west-prod", true},
		{"eu prod", "eu-west-prod", true},
		{"prod ap", "eu-west-prod", false},
		{"staging", "eu-west-prod", false},
	} {
		if got := defaultFilter(tc.typed, tc.option); got != tc.want {
			t.Errorf("defaultFilter(%q, %q) = %v, want %v", tc.typed, tc.option, got, tc.want)
		}
	}
}
