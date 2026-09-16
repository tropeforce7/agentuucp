package term

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Reading a passphrase, the same way for auu-ca's authority and auu's home.

// MinPassphrase is the shortest passphrase either program will set.
//
// The derivation is deliberately expensive, but a guess is cheap against a
// short passphrase however expensive each one is. Eight is a floor against
// a slip of the hand rather than a policy: what protects the keys is a
// passphrase nobody would guess, and no number here can check that.
const MinPassphrase = 8

// ReadPassphrase gets an existing passphrase, from a file if one was
// named, otherwise from the terminal with echo off, otherwise — standard
// input not being a terminal — from its first line.
//
// The prompt goes to stderr, because stdout is what a caller pipes.
func ReadPassphrase(prompt, file string) ([]byte, error) {
	if file != "" {
		return FromFile(file)
	}
	if IsTerminal(int(os.Stdin.Fd())) {
		return FromTerminal(prompt)
	}
	// Not a terminal: the passphrase is being piped in, one line.
	secret, err := ReadLine(os.Stdin)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("no passphrase on standard input; " +
				"pipe one in, or use --passphrase-file")
		}
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errors.New("the passphrase on standard input is empty")
	}
	return secret, nil
}

// ReadNewPassphrase gets a passphrase that is about to be set, asking twice
// when a person is typing it, since nothing else will ever check it.
func ReadNewPassphrase(prompt, file string) ([]byte, error) {
	if file == "" && IsTerminal(int(os.Stdin.Fd())) {
		first, err := FromTerminal(prompt)
		if err != nil {
			return nil, err
		}
		if err := CheckPassphrase(first); err != nil {
			return nil, err
		}
		again, err := FromTerminal("Again: ")
		if err != nil {
			return nil, err
		}
		if string(first) != string(again) {
			return nil, errors.New("the two passphrases are not the same; nothing was written")
		}
		return first, nil
	}
	secret, err := ReadPassphrase(prompt, file)
	if err != nil {
		return nil, err
	}
	return secret, CheckPassphrase(secret)
}

// CheckPassphrase refuses one shorter than MinPassphrase.
func CheckPassphrase(secret []byte) error {
	if len(secret) < MinPassphrase {
		return fmt.Errorf("a passphrase must be at least %d characters; "+
			"this one is %d", MinPassphrase, len(secret))
	}
	return nil
}

// FromFile reads the first line of a file, so that a file written with a
// trailing newline works, which is what every editor and every `echo`
// produces.
func FromFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	secret, err := ReadLine(f)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return secret, nil
}

// FromTerminal prompts with the echo off and puts back the newline the
// user's return key did not print.
func FromTerminal(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	state, err := DisableEcho(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	secret, readErr := ReadLine(os.Stdin)
	restoreErr := Restore(int(os.Stdin.Fd()), state)
	fmt.Fprintln(os.Stderr)
	if readErr != nil {
		if errors.Is(readErr, io.EOF) {
			return nil, errors.New("no passphrase given")
		}
		return nil, readErr
	}
	if restoreErr != nil {
		return nil, restoreErr
	}
	if len(secret) == 0 {
		return nil, errors.New("the passphrase is empty")
	}
	return secret, nil
}
