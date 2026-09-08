//go:build !darwin

package main

import (
	"errors"
	"io"
)

func trace(options, io.Writer) (int, error) {
	return 125, errors.New("library-call tracing is only supported on macOS")
}
