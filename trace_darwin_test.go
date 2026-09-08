package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInjectionEnv(t *testing.T) {
	got := injectionEnv([]string{"A=b=c", "DYLD_INSERT_LIBRARIES=/other.dylib", "MACHOPROXY_LOG_FD=99", "MACHOPROXY_LOG=old"}, "/hook.dylib", "3", "/new.log")
	want := []string{"A=b=c", "DYLD_INSERT_LIBRARIES=/hook.dylib:/other.dylib", "MACHOPROXY_LOG_FD=3", "MACHOPROXY_LOG=/new.log"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment = %q; want %q", got, want)
	}
}

func TestIntegration(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang is needed to build the integration fixture")
	}
	dir := t.TempDir()
	proxy := filepath.Join(dir, "machoproxy")
	fixture := filepath.Join(dir, "fixture with spaces")
	goFixture := filepath.Join(dir, "go-fixture")
	for _, args := range [][]string{
		{"go", "build", "-o", proxy, "."},
		{"clang", "-Wall", "-Wextra", "-Werror", "-o", fixture, "internal/hook/testdata/fixture.c"},
		{"go", "build", "-o", goFixture, "internal/hook/testdata/gofixture.go"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}

	t.Run("calls, argv, stdio, PID, errno and exit status", func(t *testing.T) {
		cwd := t.TempDir()
		for run := 0; run < 2; run++ {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			args := []string{"space argument", "", "-o", "literal $HOME `id` 'quotes'"}
			cmd := exec.CommandContext(ctx, proxy, append([]string{fixture}, args...)...)
			cmd.Dir = cwd
			cmd.Stdin = strings.NewReader("stdin passthrough\n")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 23 {
				t.Fatalf("target status: %v\nstdout: %s\nstderr: %s", err, &stdout, &stderr)
			}
			pid := cmd.Process.Pid
			if !strings.Contains(stdout.String(), fmt.Sprintf("pid=%d ppid=%d\n", pid, os.Getpid())) {
				t.Fatalf("target did not replace launcher: %s", &stdout)
			}
			for i, arg := range append([]string{fixture}, args...) {
				if !strings.Contains(stdout.String(), fmt.Sprintf("arg%d=%d:%s\n", i, len(arg), arg)) {
					t.Fatalf("argument %d changed: %s", i, &stdout)
				}
			}
			if !strings.Contains(stdout.String(), "stdin passthrough\n") || !strings.Contains(stderr.String(), "target stderr\n") {
				t.Fatalf("stdio changed: stdout=%q stderr=%q", &stdout, &stderr)
			}
		}
		log, err := os.ReadFile(filepath.Join(cwd, ".log"))
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range []string{"loaded backend=dyld-interpose", "open(\"fixture file.txt\"", "openat(", "write(", "read(", "rename(", "unlink(", "mmap(", "munmap(", "socket(", "connect(", "127.0.0.1:", "send(", "recv(", "errno=2", "errno=9", "<unreadable:0x1>"} {
			if !bytes.Contains(log, []byte(event)) {
				t.Errorf("missing event %q in:\n%s", event, log)
			}
		}
		if bytes.Count(log, []byte("launcher exec=")) != 2 || bytes.Count(log, []byte("loaded backend=")) != 2 {
			t.Errorf("log did not append both runs:\n%s", log)
		}
		if bytes.Count(log, []byte("open(\"/dev/null\"")) != 2*4*32 {
			t.Error("missing calls from concurrent threads")
		}
		info, err := os.Stat(filepath.Join(cwd, ".log"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("log permissions: %v, %v", info, err)
		}
	})

	t.Run("Go executable", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, proxy, goFixture)
		cmd.Dir = t.TempDir()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Go target: %v\n%s", err, out)
		}
		if !bytes.Contains(out, []byte(fmt.Sprintf("pid=%d ppid=%d\n", cmd.Process.Pid, os.Getpid()))) || !bytes.Contains(out, []byte("Go library calls\n")) {
			t.Fatalf("Go target output: %s", out)
		}
		log, err := os.ReadFile(filepath.Join(cmd.Dir, ".log"))
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range []string{"loaded backend=", "go-fixture.txt", "write(", "read("} {
			if !bytes.Contains(log, []byte(event)) {
				t.Errorf("missing Go event %q:\n%s", event, log)
			}
		}
	})

	t.Run("signal and custom log", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, proxy, "-o", "custom.log", fixture, "signal")
		cmd.Dir = t.TempDir()
		out, err := cmd.CombinedOutput()
		if err == nil || cmd.ProcessState == nil {
			t.Fatalf("expected termination: %v %s", err, out)
		}
		status := cmd.ProcessState.Sys().(syscall.WaitStatus)
		if !status.Signaled() || status.Signal() != syscall.SIGTERM {
			t.Fatalf("signal changed: %v %s", status, out)
		}
		if log, err := os.ReadFile(filepath.Join(cmd.Dir, "custom.log")); err != nil || !bytes.Contains(log, []byte("loaded backend=")) {
			t.Fatalf("custom log: %v\n%s", err, log)
		}
	})

	t.Run("reject log symlink", func(t *testing.T) {
		cwd := t.TempDir()
		log := filepath.Join(cwd, ".log")
		if err := os.Symlink(fixture, log); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(proxy, fixture)
		cmd.Dir = cwd
		out, err := cmd.CombinedOutput()
		if err == nil || !bytes.Contains(out, []byte("open log:")) {
			t.Fatalf("accepted log symlink: %v\n%s", err, out)
		}
	})
}
