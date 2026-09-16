package store

import (
	"errors"
	"fmt"
)

// ErrDamaged is a file in this home that is damaged or has been altered: not
// valid JSON, not a number, missing where its record says it is, replaced,
// or a passphrase change left half done. None of it is the AI's business to
// retry or rephrase; a person has to look at the file. The message names it
// and what to do, and auu exits 5.
var ErrDamaged = errors.New("a file in this home is damaged or has been altered")

// damagedFile is one such file: the sentence a person reads, ErrDamaged
// beneath it, and whatever else the failure was beneath that, so that a
// caller checking for an interrupted passphrase change still finds it.
type damagedFile struct {
	msg   string
	inner error
}

func (e *damagedFile) Error() string { return e.msg }

func (e *damagedFile) Unwrap() []error {
	if e.inner == nil {
		return []error{ErrDamaged}
	}
	return []error{ErrDamaged, e.inner}
}

// damaged makes the sentence: the file, the plain fact, Go's reason in
// brackets when there is one, and the knob to turn.
func damaged(path, fact string, cause error, advice string) error {
	if cause != nil {
		return &damagedFile{msg: fmt.Sprintf("%s %s (%v): %s", path, fact, cause, advice)}
	}
	return &damagedFile{msg: fmt.Sprintf("%s %s: %s", path, fact, advice)}
}
