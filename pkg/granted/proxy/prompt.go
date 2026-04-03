package proxy

import (
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/charmbracelet/lipgloss"
	accessv1alpha1 "github.com/common-fate/sdk/gen/commonfate/access/v1alpha1"
	"github.com/mattn/go-runewidth"
)

func filterMultiToken(filterValue string, optValue string, optIndex int) bool {
	optValue = strings.ToLower(optValue)
	filters := strings.Split(strings.ToLower(filterValue), " ")
	for _, filter := range filters {
		if !strings.Contains(optValue, filter) {
			return false
		}
	}
	return true
}
func PromptEntitlements(entitlements []*accessv1alpha1.Entitlement, targetHeader string, roleHeader string, promptMessage string) (*accessv1alpha1.Entitlement, error) {
	type Column struct {
		Title string
		Width int
	}
	cols := []Column{{Title: targetHeader, Width: 40}, {Title: roleHeader, Width: 40}}
	var s = make([]string, 0, len(cols))
	for _, col := range cols {
		style := lipgloss.NewStyle().Width(col.Width).MaxWidth(col.Width).Inline(true)
		renderedCell := style.Render(runewidth.Truncate(col.Title, col.Width, "…"))
		s = append(s, lipgloss.NewStyle().Bold(true).Padding(0).Render(renderedCell))
	}
	header := lipgloss.NewStyle().PaddingLeft(2).Render(lipgloss.JoinHorizontal(lipgloss.Left, s...))
	var options []string
	optionsMap := make(map[string]*accessv1alpha1.Entitlement)
	for i, entitlement := range entitlements {
		style := lipgloss.NewStyle().Width(cols[0].Width).MaxWidth(cols[0].Width).Inline(true)
		target := lipgloss.NewStyle().Bold(true).Padding(0).Render(style.Render(runewidth.Truncate(entitlement.Target.Display(), cols[0].Width, "…")))

		style = lipgloss.NewStyle().Width(cols[1].Width).MaxWidth(cols[1].Width).Inline(true)
		role := lipgloss.NewStyle().Bold(true).Padding(0).Render(style.Render(runewidth.Truncate(entitlement.Role.Display(), cols[1].Width, "…")))

		option := lipgloss.JoinHorizontal(lipgloss.Left, target, role)
		options = append(options, option)
		optionsMap[option] = entitlements[i]
	}

	originalSelectTemplate := survey.SelectQuestionTemplate
	survey.SelectQuestionTemplate = fmt.Sprintf(`
{{- define "option"}}
    {{- if eq .SelectedIndex .CurrentIndex }}{{color .Config.Icons.SelectFocus.Format }}{{ .Config.Icons.SelectFocus.Text }} {{else}}{{color "default"}}  {{end}}
    {{- .CurrentOpt.Value}}{{ if ne ($.GetDescription .CurrentOpt) "" }} - {{color "cyan"}}{{ $.GetDescription .CurrentOpt }}{{end}}
    {{- color "reset"}}
{{end}}
{{- if .ShowHelp }}{{- color .Config.Icons.Help.Format }}{{ .Config.Icons.Help.Text }} {{ .Help }}{{color "reset"}}{{"\n"}}{{end}}
{{- color .Config.Icons.Question.Format }}{{ .Config.Icons.Question.Text }} {{color "reset"}}
{{- color "default+hb"}}{{ .Message }}{{ .FilterMessage }}{{color "reset"}}
{{- if .ShowAnswer}}{{color "cyan"}} {{.Answer}}{{color "reset"}}{{"\n"}}
{{- else}}
  {{- "  "}}{{- color "cyan"}}[Use arrows to move, type to filter{{- if and .Help (not .ShowHelp)}}, {{ .Config.HelpInput }} for more help{{end}}]{{color "reset"}}
  {{- "\n"}}
%s{{- "\n"}}
  {{- range $ix, $option := .PageEntries}}
    {{- template "option" $.IterateOption $ix $option}}
  {{- end}}
{{- end}}`, header)

	var out string
	err := survey.AskOne(&survey.Select{
		Message: promptMessage,
		Options: options,
		Filter:  filterMultiToken,
	}, &out)
	if err != nil {
		return nil, err
	}

	survey.SelectQuestionTemplate = originalSelectTemplate

	return optionsMap[out], nil
}
