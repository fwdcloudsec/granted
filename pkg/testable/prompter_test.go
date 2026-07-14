package testable

import "testing"

// setNextInput installs a scripted test input for the duration of the test and
// restores the previous hook afterwards, so tests do not leak global state.
func setNextInput(t *testing.T, v StringOrBool) {
	t.Helper()
	orig := nextSurveyInput
	t.Cleanup(func() { nextSurveyInput = orig })
	nextSurveyInput = func() StringOrBool { return v }
}

func TestRequired(t *testing.T) {
	if err := Required(""); err == nil {
		t.Error("Required(\"\") = nil, want error rejecting empty input")
	}
	if err := Required("x"); err != nil {
		t.Errorf("Required(\"x\") = %v, want nil", err)
	}
}

func TestTestInputAsBool(t *testing.T) {
	tests := []struct {
		name    string
		input   StringOrBool
		want    bool
		wantErr bool
	}{
		{name: "native bool true", input: true, want: true},
		{name: "native bool false", input: false, want: false},
		{name: "parseable string true", input: "true", want: true},
		{name: "parseable string false", input: "false", want: false},
		{name: "unparseable string", input: "nope", wantErr: true},
		{name: "unexpected type", input: 5, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setNextInput(t, tt.input)
			got, err := testInputAsBool()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("testInputAsBool(%v) error = nil, want error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("testInputAsBool(%v) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("testInputAsBool(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTestInputAsString(t *testing.T) {
	tests := []struct {
		name  string
		input StringOrBool
		want  string
	}{
		{name: "string passthrough", input: "hello", want: "hello"},
		{name: "nil becomes empty", input: nil, want: ""},
		{name: "non-string is formatted", input: 7, want: "7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setNextInput(t, tt.input)
			if got := testInputAsString(); got != tt.want {
				t.Errorf("testInputAsString(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
