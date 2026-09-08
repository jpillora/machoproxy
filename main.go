package main

import (
	"debug/macho"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

type options struct {
	logPath string
	target  string
	args    []string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	opts, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "machoproxy: %v\n", err)
		return 2
	}
	code, err := trace(opts, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "machoproxy: %v\n", err)
	}
	return code
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var opts options
	flags := flag.NewFlagSet("machoproxy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opts.logPath, "o", ".log", "append trace to this file (relative to the current directory)")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: machoproxy [options] <macho binary> [args...]")
		fmt.Fprintln(stderr, "\nLog macOS library calls, then pass them through. No sudo or subprocess.")
		fmt.Fprintln(stderr, "Flags after the binary are passed unchanged to the binary.")
		fmt.Fprintln(stderr, "")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return opts, err
	}
	if flags.NArg() == 0 {
		flags.Usage()
		return opts, errors.New("missing Mach-O executable")
	}
	if opts.logPath == "" {
		return opts, errors.New("log path must not be empty")
	}
	path, err := exec.LookPath(flags.Arg(0))
	if err != nil {
		return opts, fmt.Errorf("find executable: %w", err)
	}
	opts.target, err = filepath.Abs(path)
	if err != nil {
		return opts, err
	}
	if err := validateMachO(opts.target); err != nil {
		return opts, err
	}
	opts.args = append([]string{flags.Arg(0)}, flags.Args()[1:]...)
	return opts, nil
}

func validateMachO(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("%q is not an executable file", path)
	}
	if fat, err := macho.OpenFat(path); err == nil {
		defer fat.Close()
		for _, arch := range fat.Arches {
			if arch.Type != macho.TypeExec {
				return fmt.Errorf("%q contains a Mach-O image that is not an executable", path)
			}
		}
		return nil
	}
	file, err := macho.Open(path)
	if err != nil {
		return fmt.Errorf("%q is not a supported Mach-O binary: %w", path, err)
	}
	defer file.Close()
	if file.Type != macho.TypeExec {
		return fmt.Errorf("%q is Mach-O but is not an executable", path)
	}
	return nil
}
