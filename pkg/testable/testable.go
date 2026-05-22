package testable

import (
	"fmt"
	"io"
	"testing"
)

var isTesting = false
var nextSurveyInput func() StringOrBool = func() StringOrBool { panic("not implemented") }
var validateNextOutput func(format string, a ...interface{}) = func(format string, a ...interface{}) { panic("not implemented") }

// use this type for survey inputs
type StringOrBool interface{}

// use this type for survey inputs
type SurveyInputs []StringOrBool

// configures Testable functions to utilise testing hooks
func BeginTesting() {
	isTesting = true
}

// configures Testable functions to stop utilising testing hooks
func EndTesting() {
	isTesting = false
}

// Configure this with a function that returns the next input required for a cli test
func WithNextSurveyInputFunc(next func() StringOrBool) {
	nextSurveyInput = next
}

// A helper which produces a next function that will call t.Fatal if all the inputs are exhausted
// position is an int representing the index in input for the next survey input
func NextFuncFromSlice(t *testing.T, inputs SurveyInputs, position *int) func() StringOrBool {
	return func() StringOrBool {
		if *position > len(inputs) {
			t.Fatal("attempted to call nextSurveyInput when no inputs remain")
		}
		v := inputs[*position]
		i := *position + 1
		position = &i
		return v
	}
}

func Fprintf(w io.Writer, format string, a ...interface{}) (n int, err error) {
	if isTesting {
		validateNextOutput(format, a...)
		return len([]byte(fmt.Sprintf(format, a...))), nil
	}
	n, err = fmt.Fprintf(w, format, a...)
	return
}
