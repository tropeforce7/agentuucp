// Package term is the little of a terminal auu-ca needs: to know whether a
// file descriptor is one, and to turn its echo off while a passphrase is
// typed.
//
// golang.org/x/term is the usual answer and is not a dependency this project
// takes; the two ioctls it would make are made here through syscall, on the
// two platforms the project runs on. Elsewhere IsTerminal is false and a
// passphrase is read with its echo on, which is honest rather than wrong.
package term

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// MaxLine bounds a line ReadLine will return. A passphrase is shorter.
const MaxLine = 1024

// ReadLine reads up to and not including a newline, one byte at a time so
// that nothing after the line is consumed — the caller may want the next
// line — and strips a carriage return before it. An EOF with nothing read
// is io.EOF; an EOF after some bytes ends the line.
func ReadLine(r io.Reader) ([]byte, error) {
	var line []byte
	var b [1]byte
	for {
		n, err := r.Read(b[:])
		if n == 1 {
			if b[0] == '\n' {
				return bytes.TrimSuffix(line, []byte{'\r'}), nil
			}
			if len(line) == MaxLine {
				return nil, fmt.Errorf("term: line longer than %d bytes", MaxLine)
			}
			line = append(line, b[0])
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return nil, err
			}
			if len(line) == 0 {
				return nil, io.EOF
			}
			return bytes.TrimSuffix(line, []byte{'\r'}), nil
		}
	}
}
