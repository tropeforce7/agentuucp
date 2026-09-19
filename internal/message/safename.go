package message

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tropeforce7/agentuucp/internal/channels"
)

// A received attachment name is made safe, not refused. The sender is
// held to a rule, but a receiver never depends on the sender having
// followed it: whatever name arrives, the file is written under SafeName
// of it, and uniqueness is settled at the write by an exclusive create
// and a numbered suffix, so that what the filesystem folds is folded by
// the filesystem's own answer. The sender's rule is SafeName's fixed
// point: ValidAttachmentName(name) is nil exactly when SafeName(name) ==
// name, so an honest sender never ships a name a receiver would change,
// and the sentence it gets names the step that would.

// SafeNameMaxBytes is the longest name SafeName leaves, under every
// filesystem's limit with room for a numbered suffix.
const SafeNameMaxBytes = 200

// safeNameExtBytes is the longest extension the cut keeps.
const safeNameExtBytes = 20

// safeNameFallback is the name for a name with nothing left in it.
const safeNameFallback = "attachment"

// SafeName is the name a receiver writes an attachment under, from
// whatever the sender said: deterministic, a base name, safe on every
// platform, and never empty. In order, each step on the result of the
// last:
//
//  1. Everything before the last separator of either kind is dropped.
//  2. Every rune in a forbidden category (a control, format or
//     private-use character, a line or paragraph separator), every byte
//     that is not UTF-8, and every character Windows forbids in a file
//     name (< > : " | ? *, the colon naming a drive or a stream) becomes _.
//  3. Trailing dots and spaces are trimmed, and a leading dot becomes _,
//     since a hidden file under --out is not what anyone asked for.
//  4. A stem that is a Windows device gets _ in front.
//  5. Over SafeNameMaxBytes, the name is cut on a rune boundary with the
//     extension kept when it is short.
//  6. Nothing left, or . or .., is "attachment".
//
// The six steps are one pass, and SafeName is the pass run until it
// changes nothing: the cut in step 5 can leave a stem that the earlier
// steps would have taken — spaces before the cut trimmed off to a device
// stem, or to nothing but the extension, which begins with a dot — and a
// fixed point is what the sender is held to, so it is reached by
// construction and not by the order of the steps. Each pass only shrinks
// or prefixes one underscore under the cap, so it settles in a few.
func SafeName(name string) string {
	for i := 0; i < safeNamePasses; i++ {
		next := safeNamePass(name)
		if next == name {
			return name
		}
		name = next
	}
	return safeNameFallback
}

// safeNamePasses is more passes than a name can take to settle; a name
// still changing after them is not one this program will reason about.
const safeNamePasses = 8

// safeNamePass is the six steps once.
func safeNamePass(name string) string {
	name = baseOfEither(name)
	name = replaceForbidden(name)
	name = strings.TrimRight(name, ". ")
	if strings.HasPrefix(name, ".") {
		name = "_" + name[1:]
	}
	if stem, _, _ := strings.Cut(name, "."); channels.WindowsDevice(stem) {
		name = "_" + name
	}
	name = cutToFit(name)
	if name == "" || name == "." || name == ".." {
		return safeNameFallback
	}
	return name
}

// ValidAttachmentName is the sender's rule: the name is one SafeName
// would leave as it is. The sentence names the step that would change it,
// for the sender's benefit; a receiver never runs this on what arrives.
func ValidAttachmentName(name string) error {
	if name == "" {
		return errors.New("attachment: empty name")
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("attachment %q: name is not valid UTF-8", name)
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("attachment %q: name must not contain a path separator", name)
	}
	if r, what := channels.ForbiddenRune(name); what != "" {
		return fmt.Errorf("attachment %q: name contains %U, a %s", name, r, what)
	}
	if strings.Contains(name, ":") {
		return fmt.Errorf("attachment %q: name must not contain a colon, which names a drive or a stream on Windows", name)
	}
	if i := strings.IndexAny(name, channels.WindowsForbidden); i >= 0 {
		return fmt.Errorf("attachment %q: name must not contain %q, which Windows forbids in a file name, so the name is refused for every receiver", name, name[i])
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return fmt.Errorf("attachment %q: name ends in a dot or a space, which Windows strips, so the name is refused for every receiver", name)
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("attachment %q: name begins with a dot, which hides the file where it is written, so the name is refused for every receiver", name)
	}
	if stem, _, _ := strings.Cut(name, "."); channels.WindowsDevice(stem) {
		return fmt.Errorf("attachment %q: %s is a device name on Windows, so the name is refused for every receiver", name, strings.ToUpper(stem))
	}
	if len(name) > SafeNameMaxBytes {
		return fmt.Errorf("attachment %q: name is %d bytes, over %d", name, len(name), SafeNameMaxBytes)
	}
	if SafeName(name) != name {
		// Every step above is a step of SafeName; this is the fixed
		// point said plainly, in case one is ever added there and not
		// here.
		return fmt.Errorf("attachment %q: the receiver would write it as %q", name, SafeName(name))
	}
	return nil
}

// baseOfEither is filepath.Base on both separators, whatever the
// platform: everything up to and including the last / or \ is dropped.
func baseOfEither(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// replaceForbidden makes every forbidden rune, invalid byte and Windows
// character an underscore.
func replaceForbidden(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteByte('_')
		case r == ':', channels.Forbidden(r) != "", strings.ContainsRune(channels.WindowsForbidden, r):
			b.WriteByte('_')
		default:
			b.WriteString(name[i : i+size])
		}
		i += size
	}
	return b.String()
}

// cutToFit cuts a name over SafeNameMaxBytes on a rune boundary, keeping
// a short extension. filepath.Ext is the platform's, but a name here has
// no separator left, so it is the last dot's suffix on every platform.
func cutToFit(name string) string {
	if len(name) <= SafeNameMaxBytes {
		return name
	}
	ext := filepath.Ext(name)
	if len(ext) > safeNameExtBytes || ext == name {
		ext = ""
	}
	stem := strings.TrimSuffix(name, ext)
	stem = cutRunes(stem, SafeNameMaxBytes-len(ext))
	// The cut may have left a trailing dot or space, which step 3 took.
	stem = strings.TrimRight(stem, ". ")
	return stem + ext
}

// cutRunes is s cut to at most n bytes on a rune boundary; n below zero
// is nothing kept.
func cutRunes(s string, n int) string {
	if n < 0 {
		n = 0
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// Numbered is the nth name for a safe name: the name itself for 1, and
// stem-n.ext from 2, the suffix before the extension (a.tar.gz becomes
// a.tar-2.gz, README becomes README-2). An extension over twenty bytes is
// not one, as for the cut, and the suffix goes at the end; the stem is cut
// so that the whole stays within SafeNameMaxBytes, and a stem with
// nothing left is "attachment", so the name never begins with the dash.
// The result goes through SafeName once more, so it is a fixed point
// whatever the arithmetic, and the sender's rule takes it.
func Numbered(safe string, n int) string {
	if n <= 1 {
		return safe
	}
	ext := filepath.Ext(safe)
	if ext == safe || len(ext) > safeNameExtBytes {
		ext = ""
	}
	stem := strings.TrimSuffix(safe, ext)
	suffix := "-" + strconv.Itoa(n)
	stem = strings.TrimRight(cutRunes(stem, SafeNameMaxBytes-len(suffix)-len(ext)), ". ")
	if stem == "" {
		stem = safeNameFallback
	}
	return SafeName(stem + suffix + ext)
}
