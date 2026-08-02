package testable

import (
	"os"
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"golang.org/x/term"
)

// a picker taller than this pushes earlier output off the screen; survey showed 7
const maxPickerOptions = 10

const titleRow = 1

// overridden in tests; false means stderr is not a terminal
var terminalHeight = func() (int, bool) {
	_, h, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || h <= 0 {
		return 0, false
	}
	return h, true
}

// pickerHeight only ever shrinks a picker, so short lists render at their
// natural size and gain no padding from the cap.
func pickerHeight(optionCount int) int {
	height := min(maxPickerOptions, optionCount) + titleRow
	if termHeight, ok := terminalHeight(); ok {
		// leave room for whatever was printed before the prompt
		height = min(height, termHeight-2)
	}
	return max(height, titleRow+1)
}

// defaultFilter matches options containing every token typed, so "prod eu"
// matches "eu-west-prod".
func defaultFilter(typed, option string) bool {
	option = strings.ToLower(option)
	for _, token := range strings.Fields(strings.ToLower(typed)) {
		if !strings.Contains(option, token) {
			return false
		}
	}
	return true
}

// The only keys handed to huh.Select. Everything else reaches the filter,
// including the letters huh binds by default (j/k, g/G) -- typing has to filter
// here, not navigate.
var navigationKeys = map[string]bool{
	"up": true, "down": true,
	"pgup": true, "pgdown": true,
	"ctrl+u": true, "ctrl+d": true,
	"home": true, "end": true,
}

func selectPickerKeyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.Select.Up = key.NewBinding(key.WithKeys("up"))
	km.Select.Down = key.NewBinding(key.WithKeys("down"))
	km.Select.GotoTop = key.NewBinding(key.WithKeys("home"))
	km.Select.GotoBottom = key.NewBinding(key.WithKeys("end"))
	km.Select.Left.Unbind()
	km.Select.Right.Unbind()
	// the model handles filtering, submitting and cancelling
	km.Select.Filter.Unbind()
	km.Select.SetFilter.Unbind()
	km.Select.ClearFilter.Unbind()
	km.Select.Submit.Unbind()
	km.Select.Next.Unbind()
	km.Select.Prev.Unbind()
	return km
}

// selectPickerModel drives a huh.Select holding only the current matches.
//
// The field is rebuilt on every filter change rather than filtered in place:
// huh keeps the pre-filter cursor and leaves the viewport scrolled past the
// earlier matches, so a search matching four options can show one
// (charmbracelet/huh#669), and that state is unexported so it cannot be
// repaired from here. Running the field directly rather than in a huh.Form is
// what leaves ESC free to clear the filter, since a Form matches its own Quit
// binding before the field sees the key.
type selectPickerModel struct {
	message  string
	options  []string
	filter   string
	validate func(string) error

	sel       *huh.Select[string]
	keymap    *huh.KeyMap
	height    int
	choice    string
	chosen    bool
	quitting  bool
	err       error
	hasDarkBg bool
}

func newSelectPickerModel(message string, options []string, validate func(string) error) selectPickerModel {
	m := selectPickerModel{
		message:  message,
		options:  options,
		validate: validate,
		keymap:   selectPickerKeyMap(),
		height:   pickerHeight(len(options)),
	}
	m.sel = m.buildSelect()
	return m
}

func (m selectPickerModel) matches() []string {
	if m.filter == "" {
		return m.options
	}
	var out []string
	for _, o := range m.options {
		if defaultFilter(m.filter, o) {
			out = append(out, o)
		}
	}
	return out
}

// title appends any active filter to the message, as survey did. No "/" prefix:
// typing filters directly, and a slash would advertise a mode that does not exist.
func (m selectPickerModel) title() string {
	if m.filter == "" {
		return m.message
	}
	return m.message + "  " + filterLabelStyle.Render("filter: "+m.filter)
}

// buildSelect returns a field holding only the current matches, starting at the
// first with an unscrolled viewport.
func (m selectPickerModel) buildSelect() *huh.Select[string] {
	matches := m.matches()
	sel := huh.NewSelect[string]().
		Title(m.title()).
		Options(huh.NewOptions(matches...)...)
	sel.WithTheme(huhThemeOpt)
	sel.WithKeyMap(m.keymap)
	sel.WithHeight(min(m.height, len(matches)+titleRow))
	sel.Focus()
	sel.Init()
	return sel
}

func (m selectPickerModel) Init() tea.Cmd { return nil }

func (m selectPickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.BackgroundColorMsg:
		// remembered so it can be replayed onto every rebuilt field
		m.hasDarkBg = msg.IsDark()
		m.sel.Update(msg)
		return m, nil
	case tea.WindowSizeMsg:
		// only shrink; growing here would bring back the full-screen list
		m.height = min(m.height, msg.Height-2)
		m.sel = m.buildSelect()
		return m, nil
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	m.sel.Update(msg)
	return m, nil
}

func (m selectPickerModel) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	s := msg.String()
	// clear any rejection; a failed Enter sets it again below
	m.err = nil

	switch s {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "enter":
		value, ok := m.sel.GetValue().(string)
		if !ok || len(m.matches()) == 0 {
			return m, nil
		}
		if m.validate != nil {
			if err := m.validate(value); err != nil {
				// stay open so the user can pick again
				m.err = err
				return m, nil
			}
		}
		m.choice, m.chosen = value, true
		return m, tea.Quit
	case "esc":
		// esc clears an active filter, otherwise cancels
		if m.filter != "" {
			return m.setFilter(""), nil
		}
		m.quitting = true
		return m, tea.Quit
	case "backspace":
		if m.filter != "" {
			return m.setFilter(m.filter[:len(m.filter)-1]), nil
		}
		return m, nil
	}

	if navigationKeys[s] {
		m.sel.Update(msg)
		return m, nil
	}

	// any other printable character extends the filter
	if len(s) == 1 && s[0] >= 0x20 && s[0] <= 0x7e {
		return m.setFilter(m.filter + s), nil
	}
	return m, nil
}

func (m selectPickerModel) setFilter(filter string) selectPickerModel {
	m.filter = filter
	m.sel = m.buildSelect()
	if m.hasDarkBg {
		m.sel.Update(tea.BackgroundColorMsg{})
	}
	return m
}

func (m selectPickerModel) View() tea.View {
	if m.quitting || m.chosen {
		return tea.NewView("")
	}
	view := m.sel.View()
	if len(m.matches()) == 0 {
		view = validationErrorStyle.Render(m.title() + "  no matches")
	}
	if m.err != nil {
		view += "\n" + validationErrorStyle.Render(m.err.Error())
	}
	view += "\n" + helpStyle.Render("letters filter • ↑/↓ move • enter select • esc clear/cancel")
	return tea.NewView(view)
}

func (h *huhPrompter) runPicker(message string, options []string, validate func(string) error) (string, error) {
	if isTesting {
		return testInputAsString(), nil
	}

	final, err := tea.NewProgram(
		newSelectPickerModel(message, options, validate),
		tea.WithInput(h.stdin),
		tea.WithOutput(h.stdout),
	).Run()
	if err != nil {
		return "", err
	}
	if m, ok := final.(selectPickerModel); ok {
		if m.quitting {
			return "", huh.ErrUserAborted
		}
		return m.choice, nil
	}
	return "", nil
}
