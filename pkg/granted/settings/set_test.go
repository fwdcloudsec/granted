package settings

import (
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func ptrString(s string) *string { return &s }

func TestFieldOptions(t *testing.T) {
	type input struct {
		A string
		B struct {
			C string
			D *string
		}
	}
	tests := []struct {
		name  string
		input any
		want  []string
		want1 map[string]field
	}{
		{
			name:  "ok",
			input: input{},
			want:  []string{"A", "B.C"},
		},
		{
			name:  "ok",
			input: &input{},
			want:  []string{"A", "B.C"},
		},
		{
			name: "ok",
			input: &input{
				A: "A",
				B: struct {
					C string
					D *string
				}{
					C: "C",
					D: ptrString("D"),
				},
			},
			want: []string{"A", "B.C", "B.D"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FieldOptions(tt.input)
			keys := make([]string, 0, len(got))
			for k := range got {
				keys = append(keys, k)
			}

			//sort to make sure the keys are in the correct order for the test
			slices.Sort(keys)

			assert.Equal(t, tt.want, keys)
		})
	}
}

func TestKeyringFields_Value(t *testing.T) {
	t.Run("nil outer pointer returns empty string", func(t *testing.T) {
		f := keyringFields{field: nil}
		assert.Equal(t, "", f.Value())
	})

	t.Run("uninitialised double pointer returns empty string", func(t *testing.T) {
		var inner *string
		f := keyringFields{field: &inner}
		assert.Equal(t, "", f.Value())
	})

	t.Run("initialised value is returned", func(t *testing.T) {
		inner := ptrString("file")
		f := keyringFields{field: &inner}
		assert.Equal(t, "file", f.Value())
	})
}

func TestKeyringFields_Set(t *testing.T) {
	t.Run("initialises a nil pointer before setting", func(t *testing.T) {
		var inner *string
		f := keyringFields{field: &inner}

		assert.NoError(t, f.Set("file"))
		assert.NotNil(t, inner)
		assert.Equal(t, "file", *inner)
	})

	t.Run("overwrites an existing value", func(t *testing.T) {
		inner := ptrString("old")
		f := keyringFields{field: &inner}

		assert.NoError(t, f.Set("new"))
		assert.Equal(t, "new", *inner)
	})
}

func TestKeyringFields_Kind(t *testing.T) {
	f := keyringFields{}
	assert.Equal(t, reflect.String, f.Kind())
}
