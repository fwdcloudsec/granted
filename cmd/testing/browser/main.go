package main

import (
	"fmt"
	"os"
)

// This package is used to test browser features in tests
func main() {
	// Make sure we can handle a browser printing something stdout (like Chrome does)
	fmt.Println("Opening in existing browser session.")
	os.Exit(0)
}
