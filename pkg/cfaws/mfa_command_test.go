package cfaws

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunMfaCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses unix test scripts")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "mfa.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"$1:$GRANTED_MFA_SERIAL\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	code, err := runMfaCommand(script+` "two words"`, "arn:mfa")
	if err != nil || code != "two words:arn:mfa" {
		t.Fatalf("got %q, %v", code, err)
	}
	if _, err := runMfaCommand("true", ""); err == nil {
		t.Fatal("expected error on empty output")
	}
	if _, err := runMfaCommand("false", ""); err == nil {
		t.Fatal("expected error on failing command")
	}
	if _, err := runMfaCommand("   ", ""); err == nil {
		t.Fatal("expected error on empty command")
	}
	if _, err := runMfaCommand(`echo "unterminated`, ""); err == nil {
		t.Fatal("expected error on unbalanced quote")
	}
}
