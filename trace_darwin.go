package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The universal dylib is built ahead of time. Running machoproxy never invokes
// a compiler, shell, helper process, or tracer process.
//go:generate clang -dynamiclib -arch arm64 -arch x86_64 -mmacosx-version-min=11.0 -O2 -Wall -Wextra -Werror -o internal/hook/machoproxy.dylib internal/hook/hook.c

//go:embed internal/hook/machoproxy.dylib
var hookLibrary []byte

func trace(opts options, stderr io.Writer) (int, error) {
	logPath, err := filepath.Abs(opts.logPath)
	if err != nil {
		return 125, err
	}
	// The log is inherited across exec; dyld needs no pathname permissions or
	// environment-variable lookup to reopen it. Append, never truncate.
	log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return 125, fmt.Errorf("open log: %w", err)
	}
	defer log.Close()
	info, err := log.Stat()
	if err != nil {
		return 125, err
	}
	if !info.Mode().IsRegular() {
		return 125, fmt.Errorf("log %q must be a regular file", logPath)
	}
	targetInfo, err := os.Stat(opts.target)
	if err != nil {
		return 125, err
	}
	if os.SameFile(info, targetInfo) {
		return 125, fmt.Errorf("log must not be the target executable")
	}
	if targetInfo.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return 125, fmt.Errorf("setuid/setgid executables cannot be injected by dyld")
	}
	// SF_RESTRICTED is defined by Darwin's sys/stat.h, but not Go's syscall
	// package. dyld strips injection settings for these system executables.
	if stat, ok := targetInfo.Sys().(*syscall.Stat_t); ok && stat.Flags&0x00080000 != 0 {
		return 125, fmt.Errorf("%q is SIP-protected; dyld injection requires an unrestricted executable, such as a local development build", opts.target)
	}
	library, err := installHook()
	if err != nil {
		return 125, fmt.Errorf("prepare injected library: %w", err)
	}
	args, _ := json.Marshal(opts.args)
	if _, err := fmt.Fprintf(log, "\n%s pid=%d launcher exec=%q argv=%s log=%q\n", time.Now().UTC().Format(time.RFC3339Nano), os.Getpid(), opts.target, args, logPath); err != nil {
		return 125, fmt.Errorf("write log: %w", err)
	}
	fd := log.Fd()
	// Go opens files with FD_CLOEXEC. Keep this one descriptor for the dylib.
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, 0); errno != 0 {
		return 125, fmt.Errorf("inherit log descriptor: %w", errno)
	}
	env := injectionEnv(os.Environ(), library, fmt.Sprint(fd), logPath)
	fmt.Fprintf(stderr, "machoproxy: logging to %s\n", logPath)
	// exec replaces this process. The target retains our PID, cwd, stdio,
	// credentials, terminal, and the normal signal/exit-status behavior.
	if err := syscall.Exec(opts.target, opts.args, env); err != nil {
		fmt.Fprintf(log, "%s pid=%d launcher exec_error=%q\n", time.Now().UTC().Format(time.RFC3339Nano), os.Getpid(), err)
		return 126, fmt.Errorf("exec target: %w", err)
	}
	panic("exec returned without an error")
}

func injectionEnv(env []string, library, fd, logPath string) []string {
	var existing string
	out := make([]string, 0, len(env)+3)
	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		switch key {
		case "DYLD_INSERT_LIBRARIES":
			existing = value
		case "MACHOPROXY_LOG_FD", "MACHOPROXY_LOG":
		default:
			out = append(out, entry)
		}
	}
	if existing != "" {
		library += ":" + existing
	}
	return append(out, "DYLD_INSERT_LIBRARIES="+library, "MACHOPROXY_LOG_FD="+fd, "MACHOPROXY_LOG="+logPath)
}

func installHook() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cache, "machoproxy")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("hook-%x.dylib", sha256.Sum256(hookLibrary)))
	if data, err := os.ReadFile(path); err == nil && bytes.Equal(data, hookLibrary) {
		return path, nil
	}
	file, err := os.CreateTemp(dir, ".hook-*.dylib")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(hookLibrary); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Chmod(0500); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}
