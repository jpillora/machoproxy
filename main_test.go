package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectNonMachO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateMachO(path); err == nil {
		t.Fatal("accepted a shell script as Mach-O")
	}
}

func TestUsage(t *testing.T) {
	if code := run([]string{"-h"}, io.Discard); code != 0 {
		t.Fatalf("help status = %d", code)
	}
	if code := run(nil, io.Discard); code != 2 {
		t.Fatalf("missing target status = %d", code)
	}
}
