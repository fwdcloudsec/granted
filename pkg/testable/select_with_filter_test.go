package testable

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestRankFilter(t *testing.T) {
	targets := []string{"alpha", "beta", "gamma"}
	// The filter receives (term, option); this matcher accepts options that
	// contain the term, matching how callers use SelectWithFilter.
	contains := func(term, option string) bool { return strings.Contains(option, term) }

	t.Run("empty term returns every target in order", func(t *testing.T) {
		got := rankFilter("", targets, contains)
		if len(got) != len(targets) {
			t.Fatalf("got %d ranks, want %d", len(got), len(targets))
		}
		for i, r := range got {
			if r.Index != i {
				t.Errorf("rank[%d].Index = %d, want %d", i, r.Index, i)
			}
		}
	})

	t.Run("non-empty term keeps only matches, by original index", func(t *testing.T) {
		got := rankFilter("bet", targets, contains)
		if len(got) != 1 || got[0].Index != 1 {
			t.Fatalf("term \"bet\": got %+v, want a single rank with Index=1", got)
		}
	})

	t.Run("no matches returns an empty result", func(t *testing.T) {
		if got := rankFilter("zzz", targets, contains); len(got) != 0 {
			t.Errorf("term \"zzz\": got %d ranks, want 0", len(got))
		}
	})
}

func TestSelectFilterModelUpdate(t *testing.T) {
	options := []string{"alpha", "beta", "gamma"}
	contains := func(term, option string) bool { return strings.Contains(option, term) }
	newModel := func() selectFilterModel { return newSelectFilterModel("pick", options, contains) }

	press := func(m selectFilterModel, k tea.Key) selectFilterModel {
		next, _ := m.Update(tea.KeyPressMsg(k))
		return next.(selectFilterModel)
	}
	typed := func(m selectFilterModel, s string) selectFilterModel {
		for _, r := range s {
			m = press(m, tea.Key{Code: r, Text: string(r)})
		}
		return m
	}

	t.Run("enter selects the highlighted option", func(t *testing.T) {
		m := press(newModel(), tea.Key{Code: tea.KeyEnter})
		if m.quitting {
			t.Error("enter set quitting = true, want false")
		}
		if m.choice != "alpha" {
			t.Errorf("choice = %q, want %q (first option is highlighted by default)", m.choice, "alpha")
		}
	})

	t.Run("ctrl+c cancels without a choice", func(t *testing.T) {
		m := press(newModel(), tea.Key{Code: 'c', Mod: tea.ModCtrl})
		if !m.quitting {
			t.Error("ctrl+c did not set quitting = true")
		}
		if m.choice != "" {
			t.Errorf("choice = %q, want empty on cancel", m.choice)
		}
	})

	t.Run("esc with no active filter cancels", func(t *testing.T) {
		m := press(newModel(), tea.Key{Code: tea.KeyEscape})
		if !m.quitting {
			t.Error("esc with no filter did not set quitting = true")
		}
	})

	// This is the behavior the survey->huh migration set out to add: ESC first
	// clears an active filter and only cancels the picker on a second press.
	t.Run("esc with an active filter clears it instead of cancelling", func(t *testing.T) {
		m := typed(newModel(), "be")
		if got := m.list.FilterValue(); got != "be" {
			t.Fatalf("precondition: FilterValue = %q, want %q", got, "be")
		}
		m = press(m, tea.Key{Code: tea.KeyEscape})
		if m.quitting {
			t.Error("esc cleared the filter but also set quitting = true, want false")
		}
		if got := m.list.FilterValue(); got != "" {
			t.Errorf("FilterValue after clearing esc = %q, want empty", got)
		}
	})

	t.Run("printable characters build up the filter", func(t *testing.T) {
		m := typed(newModel(), "al")
		if got := m.list.FilterValue(); got != "al" {
			t.Errorf("FilterValue = %q, want %q", got, "al")
		}
	})

	t.Run("backspace shortens the filter, then clears it", func(t *testing.T) {
		m := typed(newModel(), "al")
		m = press(m, tea.Key{Code: tea.KeyBackspace})
		if got := m.list.FilterValue(); got != "a" {
			t.Errorf("FilterValue after one backspace = %q, want %q", got, "a")
		}
		m = press(m, tea.Key{Code: tea.KeyBackspace})
		if got := m.list.FilterValue(); got != "" {
			t.Errorf("FilterValue after final backspace = %q, want empty", got)
		}
	})
}
