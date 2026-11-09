package settings

import (
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
