package testable

import (
	"charm.land/bubbles/v2/list"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// grantedTheme is ThemeCharm with the fuchsia/indigo accents replaced by
// terminal-friendly cyan and bold, keeping the form layout intact. Colors
// are specified as ANSI 16 indices ("6" cyan, "7" white) so they pick up
// whatever palette the user's terminal theme defines, rather than hard-
// coded hex values that ignore the terminal's color scheme.
func grantedTheme(isDark bool) *huh.Styles {
	t := huh.ThemeCharm(isDark)

	cyan := lipgloss.Color("6")
	green := lipgloss.Color("2")
	black := lipgloss.Color("0")
	dim := lipgloss.Color("243")

	// Drop huh's outer left-bar that wraps each focused field; the prompts
	// in this project read as single-field interactions, so the "this field
	// has focus" indicator is just noise.
	noFrame := lipgloss.NewStyle()
	t.Focused.Base = noFrame
	t.Focused.Card = noFrame
	t.Blurred.Base = noFrame
	t.Blurred.Card = noFrame

	// Title was indigo + bold; keep bold but drop the indigo so it picks up
	// the terminal's default foreground.
	t.Focused.Title = lipgloss.NewStyle().Bold(true)
	t.Focused.NoteTitle = lipgloss.NewStyle().Bold(true).MarginBottom(1)
	t.Blurred.Title = t.Focused.Title
	t.Blurred.NoteTitle = t.Focused.NoteTitle
	t.Group.Title = t.Focused.Title

	// Anywhere ThemeCharm used fuchsia, use cyan.
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(cyan)
	t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(cyan)
	t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(cyan)
	t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(cyan)
	t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(black).Background(cyan)
	// ThemeCharm defaults SelectedOption to a hex green that doesn't pick up
	// the terminal palette; swap to ANSI green so it matches the filter
	// picker's focused row.
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(green)
	t.Focused.Next = t.Focused.FocusedButton
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(cyan)

	// Description tint was tied to ThemeCharm's indigo-ish palette; force
	// a plain dim instead.
	t.Focused.Description = lipgloss.NewStyle().Foreground(dim)
	t.Blurred.Description = t.Focused.Description
	t.Group.Description = t.Focused.Description

	// Mirror the changed bits onto the blurred state.
	t.Blurred.SelectSelector = t.Focused.SelectSelector
	t.Blurred.NextIndicator = t.Focused.NextIndicator
	t.Blurred.PrevIndicator = t.Focused.PrevIndicator
	t.Blurred.MultiSelectSelector = t.Focused.MultiSelectSelector
	t.Blurred.FocusedButton = t.Focused.FocusedButton
	t.Blurred.TextInput.Prompt = t.Focused.TextInput.Prompt

	return t
}

// huhThemeOpt is the form option that applies grantedTheme.
var huhThemeOpt = huh.ThemeFunc(grantedTheme)

// applyDelegateStyles mutates a bubbles/list DefaultDelegate so the focused
// row uses cyan instead of the default fuchsia. The default styles include
// padding and a left-border that aligns the selected row's text with the
// unselected rows; preserve those by chaining onto the existing styles
// rather than building new ones from scratch.
//
// Call before list.New — the list copies the delegate by value at
// construction time, so mutating the local variable afterwards has no effect.
func applyDelegateStyles(d *list.DefaultDelegate) {
	cyan := lipgloss.Color("6")
	// ANSI 2 picks up the terminal's "green" — same role as huh.Select's
	// SelectedOption color, just palette-respecting instead of hex-locked.
	green := lipgloss.Color("2")
	dim := lipgloss.Color("243")

	// Replace the default per-row left-border indicator with a `>` cursor
	// to match huh.Select's focus marker (and by extension survey's `❯`).
	// Border is cyan (matching SelectSelector), text is green (matching
	// SelectedOption) — same two-color treatment huh.Select uses.
	cursorBorder := lipgloss.Border{Left: ">"}
	d.Styles.SelectedTitle = d.Styles.SelectedTitle.
		Border(cursorBorder, false, false, false, true).
		BorderForeground(cyan).
		Foreground(green).
		Padding(0, 0, 0, 1)
	d.Styles.SelectedDesc = d.Styles.SelectedDesc.
		Border(cursorBorder, false, false, false, true).
		BorderForeground(cyan).
		Foreground(green).
		Padding(0, 0, 0, 1)
	d.Styles.DimmedTitle = d.Styles.DimmedTitle.Foreground(dim)
	d.Styles.DimmedDesc = d.Styles.DimmedDesc.Foreground(dim)
	d.Styles.FilterMatch = lipgloss.NewStyle().Underline(true)
}

// applyListStyles mutates a bubbles/list Model so its chrome matches the
// huh.Select aesthetic: bold-neutral title, flush-left bars. The status
// bar stays visible — it's the only feedback channel for showing what
// the user has typed into the filter (rendered as `"<filter>" N items`).
// The defaults indent every bar 2 chars and add a blank line between
// sections, which makes the picker look more padded than the other prompts.
func applyListStyles(l *list.Model) {
	l.Styles.Title = lipgloss.NewStyle().Bold(true)
	l.Styles.TitleBar = lipgloss.NewStyle()
	l.Styles.StatusBar = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	l.Styles.HelpStyle = lipgloss.NewStyle().PaddingTop(1)
	l.Styles.PaginationStyle = lipgloss.NewStyle()
}
