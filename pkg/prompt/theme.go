package prompt

import (
	"sync"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

type theme struct{}

var (
	darkStyles  = sync.OnceValue(func() *huh.Styles { return grantedTheme(true) })
	lightStyles = sync.OnceValue(func() *huh.Styles { return grantedTheme(false) })
)

func (theme) Theme(isDark bool) *huh.Styles {
	if isDark {
		return darkStyles()
	}
	return lightStyles()
}

func grantedTheme(isDark bool) *huh.Styles {
	t := huh.ThemeCharm(isDark)

	cyan := lipgloss.Color("6")
	green := lipgloss.Color("2")
	black := lipgloss.Color("0")
	dim := lipgloss.Color("243")

	// drop huh's outer left-bar around the focused field
	noFrame := lipgloss.NewStyle()
	t.Focused.Base = noFrame
	t.Focused.Card = noFrame
	t.Blurred.Base = noFrame
	t.Blurred.Card = noFrame

	t.Focused.Title = lipgloss.NewStyle().Bold(true)
	t.Focused.NoteTitle = lipgloss.NewStyle().Bold(true).MarginBottom(1)
	t.Blurred.Title = t.Focused.Title
	t.Blurred.NoteTitle = t.Focused.NoteTitle
	t.Group.Title = t.Focused.Title

	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(cyan)
	t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(cyan)
	t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(cyan)
	t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(cyan)
	t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(black).Background(cyan)
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(green)
	t.Focused.Next = t.Focused.FocusedButton
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(cyan)

	t.Focused.Description = lipgloss.NewStyle().Foreground(dim)
	t.Blurred.Description = t.Focused.Description
	t.Group.Description = t.Focused.Description

	t.Blurred.SelectSelector = t.Focused.SelectSelector
	t.Blurred.NextIndicator = t.Focused.NextIndicator
	t.Blurred.PrevIndicator = t.Focused.PrevIndicator
	t.Blurred.MultiSelectSelector = t.Focused.MultiSelectSelector
	t.Blurred.FocusedButton = t.Focused.FocusedButton
	t.Blurred.TextInput.Prompt = t.Focused.TextInput.Prompt

	return t
}
