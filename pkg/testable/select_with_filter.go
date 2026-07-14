package testable

import (
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
)

// SelectWithFilter shows a single-choice list with a custom filter function
// that decides which options match the user's typed text. Typing any
// printable character appends to the filter; arrows navigate; Enter selects;
// Esc clears the filter if any, otherwise cancels and returns huh.ErrUserAborted.
//
// In testing mode the filter is ignored and one value is consumed from the
// input stream configured by WithNextSurveyInputFunc.
func SelectWithFilter(message string, options []string, filter func(term, option string) bool) (string, error) {
	return defaultPrompter.SelectWithFilter(message, options, filter)
}

type filterItem struct{ value string }

func (i filterItem) FilterValue() string { return i.value }
func (i filterItem) Title() string       { return i.value }
func (i filterItem) Description() string { return "" }

type selectFilterModel struct {
	list     list.Model
	choice   string
	quitting bool
}

func (m selectFilterModel) Init() tea.Cmd { return nil }

func (m selectFilterModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, msg.Height-2)
	case tea.KeyPressMsg:
		s := msg.String()
		switch s {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "enter":
			if i, ok := m.list.SelectedItem().(filterItem); ok {
				m.choice = i.value
			}
			return m, tea.Quit
		case "esc":
			// Esc clears the filter when one is active; otherwise quits.
			if m.list.FilterValue() != "" {
				m.list.ResetFilter()
				return m, nil
			}
			m.quitting = true
			return m, tea.Quit
		case "up", "down", "pgup", "pgdown", "home", "end":
			var cmd tea.Cmd
			m.list, cmd = m.list.Update(msg)
			return m, cmd
		case "backspace":
			cur := m.list.FilterValue()
			if len(cur) > 0 {
				newFilter := cur[:len(cur)-1]
				if newFilter == "" {
					m.list.ResetFilter()
				} else {
					m.list.SetFilterText(newFilter)
				}
			}
			return m, nil
		}
		// Any other printable single character appends to the filter,
		// matching survey's type-to-filter behavior.
		if len(s) == 1 && s[0] >= 0x20 && s[0] <= 0x7e {
			m.list.SetFilterText(m.list.FilterValue() + s)
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m selectFilterModel) View() tea.View {
	if m.quitting || m.choice != "" {
		return tea.NewView("")
	}
	return tea.NewView(m.list.View())
}

func (h *huhPrompter) SelectWithFilter(message string, options []string, filter func(term, option string) bool) (string, error) {
	if isTesting {
		return testInputAsString(), nil
	}

	m := newSelectFilterModel(message, options, filter)
	p := tea.NewProgram(m, tea.WithInput(h.stdin), tea.WithOutput(h.stdout))
	final, err := p.Run()
	if err != nil {
		return "", err
	}
	if m, ok := final.(selectFilterModel); ok {
		if m.quitting {
			return "", huh.ErrUserAborted
		}
		return m.choice, nil
	}
	return "", nil
}

// rankFilter ranks targets against term using match. An empty term matches
// everything, preserving order; otherwise only targets that match accepts are
// returned. This is the pure logic behind the bubbles/list Filter hook, split
// out so it can be unit-tested without a running program.
func rankFilter(term string, targets []string, match func(term, option string) bool) []list.Rank {
	if term == "" {
		ranks := make([]list.Rank, len(targets))
		for i := range targets {
			ranks[i] = list.Rank{Index: i}
		}
		return ranks
	}
	ranks := []list.Rank{}
	for i, target := range targets {
		if match(term, target) {
			ranks = append(ranks, list.Rank{Index: i})
		}
	}
	return ranks
}

// newSelectFilterModel builds the bubbles/list-backed model used by
// SelectWithFilter. It is separated from SelectWithFilter so tests can drive
// the same model production uses without opening a terminal.
func newSelectFilterModel(message string, options []string, filter func(term, option string) bool) selectFilterModel {
	items := make([]list.Item, len(options))
	for i, o := range options {
		items[i] = filterItem{value: o}
	}

	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	delegate.SetSpacing(0)
	// Surface the bindings we actually handle. The "/" in the first entry
	// exists only so key.Binding.Enabled() returns true; the help text
	// describes the behavior (typing any printable character appends to the
	// filter, handled in Update below — not by bubbles/list itself).
	delegate.ShortHelpFunc = func() []key.Binding {
		return []key.Binding{
			key.NewBinding(key.WithKeys("/"), key.WithHelp("letters", "filter")),
			key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
			key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "clear/cancel")),
		}
	}

	applyDelegateStyles(&delegate)

	l := list.New(items, delegate, 80, 18)
	l.Title = message
	l.SetFilteringEnabled(true)
	applyListStyles(&l)
	// Replace bubbles/list's default keymap with bindings that match what our
	// Update method actually wires up; otherwise the help row advertises `/`
	// filter, `q` quit, and j/k vim navigation that don't apply here.
	l.KeyMap.CursorUp = key.NewBinding(key.WithKeys("up"), key.WithHelp("↑", "up"))
	l.KeyMap.CursorDown = key.NewBinding(key.WithKeys("down"), key.WithHelp("↓", "down"))
	l.KeyMap.Filter.Unbind()
	l.KeyMap.ClearFilter.Unbind()
	l.KeyMap.NextPage.Unbind()
	l.KeyMap.PrevPage.Unbind()
	l.KeyMap.GoToStart.Unbind()
	l.KeyMap.GoToEnd.Unbind()
	l.KeyMap.Quit.Unbind()
	l.KeyMap.ForceQuit.Unbind()
	l.KeyMap.ShowFullHelp.Unbind()
	l.KeyMap.CloseFullHelp.Unbind()
	l.Filter = func(term string, targets []string) []list.Rank {
		return rankFilter(term, targets, filter)
	}

	return selectFilterModel{list: l}
}
