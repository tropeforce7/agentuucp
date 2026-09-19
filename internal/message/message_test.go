package message

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func goodBody(t *testing.T) Body {
	t.Helper()
	a, err := NewAttachment("Report.java", []byte("class Report {}"))
	if err != nil {
		t.Fatal(err)
	}
	return Body{Type: TypeAsk, Subject: "s", Thread: "0123456789abcdef0123456789abcdef", Text: "hello", Attachments: []Attachment{a}}
}

func TestValidateAccepts(t *testing.T) {
	b := goodBody(t)
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.Attachments[0].Media != "text/x-java-source; charset=utf-8" && !strings.HasPrefix(b.Attachments[0].Media, "text/") {
		// Media type tables vary by platform; only require a non-default guess or the default.
		if b.Attachments[0].Media != DefaultMedia {
			t.Fatalf("unexpected media %q", b.Attachments[0].Media)
		}
	}
}

func TestValidateRejectsType(t *testing.T) {
	b := goodBody(t)
	b.Type = "exec"
	if err := b.Validate(); err == nil {
		t.Fatal("accepted unknown type")
	}
	b.Type = ""
	if err := b.Validate(); err == nil {
		t.Fatal("accepted empty type")
	}
}

func TestValidateRejectsMissingThread(t *testing.T) {
	b := goodBody(t)
	b.Thread = ""
	if err := b.Validate(); err == nil {
		t.Fatal("accepted empty thread")
	}
}

// A bad attachment name is the sender's to fix and the receiver's to make
// safe: the sender's rule refuses each, and Body.Validate, which both
// sides run, takes it, so a receiver writes the file under SafeName of it
// rather than refusing the message. What Validate still refuses of a name
// is what it refuses of any text: over the byte cap here, and elsewhere
// a line break, a NUL and bytes that are not UTF-8.
func TestASenderMayNotShipABadAttachmentName(t *testing.T) {
	data := []byte("x")
	sum := sha256.Sum256(data)
	for _, name := range []string{"", "..", ".", "a/b", "../x", "..\\x", "dir/../x", "CON", "a<b"} {
		if err := ValidAttachmentNames([]string{name}); err == nil {
			t.Errorf("the sender's rule took %q", name)
		}
		a := Attachment{Name: name, Media: DefaultMedia, Size: 1, SHA256: hex.EncodeToString(sum[:]), Data: data}
		b := Body{Type: TypeNote, Thread: "0123456789abcdef0123456789abcdef", Attachments: []Attachment{a}}
		if err := b.Validate(); err != nil {
			t.Errorf("Validate refused the name %q, which is the receiver's to make safe: %v", name, err)
		}
	}
	over := strings.Repeat("n", 256)
	a := Attachment{Name: over, Media: DefaultMedia, Size: 1, SHA256: hex.EncodeToString(sum[:]), Data: data}
	b := Body{Type: TypeNote, Thread: "0123456789abcdef0123456789abcdef", Attachments: []Attachment{a}}
	if err := b.Validate(); err == nil || !strings.Contains(err.Error(), "longer than 255 bytes") {
		t.Errorf("a 256-byte name at Validate: %v, want the text rule", err)
	}
}

func TestValidateRejectsDigestAndSizeMismatch(t *testing.T) {
	b := goodBody(t)
	b.Attachments[0].Data = append(b.Attachments[0].Data, '!')
	if err := b.Validate(); err == nil {
		t.Fatal("accepted size mismatch")
	}

	b = goodBody(t)
	b.Attachments[0].SHA256 = strings.Repeat("0", 64)
	if err := b.Validate(); err == nil {
		t.Fatal("accepted digest mismatch")
	}
}

// Two attachments with one name are the sender's to fix; a receiver
// writes the second beside the first with a numbered suffix.
func TestASenderMayNotShipDuplicateNames(t *testing.T) {
	a, _ := NewAttachment("x.txt", []byte("a"))
	b := Body{Type: TypeNote, Thread: "0123456789abcdef0123456789abcdef", Attachments: []Attachment{a, a}}
	if err := ValidAttachmentNames(b.AttachmentNames()); err == nil || !strings.Contains(err.Error(), "duplicate attachment name") {
		t.Errorf("the sender's rule: %v, want the duplicate named", err)
	}
	if err := b.Validate(); err != nil {
		t.Errorf("Validate refused a duplicate name, which is settled at the write: %v", err)
	}
}

func TestNewAttachmentStripsDirectories(t *testing.T) {
	a, err := NewAttachment("/etc/passwd", []byte("root:x:0:0"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != "passwd" {
		t.Fatalf("name %q", a.Name)
	}
}

// A thread id is a message id, and so is in_reply_to: 32 lowercase hex
// characters, the shape envelope.NewID makes and nothing else. The second
// adversarial trace sent `--thread "../../outside"` to an expert host, which
// joined it onto its serve directory and stopped for good; the shape is
// held here, where every message passes on both sides of the wire.
func TestValidIDHoldsTheShapeOfAMessageID(t *testing.T) {
	const good = "0123456789abcdef0123456789abcdef"
	if err := ValidID(good); err != nil {
		t.Fatalf("a message id was refused: %v", err)
	}
	for _, s := range []string{
		"",
		good[:31],
		good + "0",
		"0123456789ABCDEF0123456789abcdef",
		"0123456789abcdef0123456789abcde/",
		"0123456789abcdef0123456789abcde.",
		"../../outside",
		"..",
		".",
		"0123456789abcdef0123456789abcde\x00",
		"0123456789abcdef0123456789abcdé",
	} {
		if err := ValidID(s); err == nil {
			t.Errorf("%q was accepted as a message id", s)
		}
	}
}

func TestValidateHoldsThreadAndInReplyToToTheIDShape(t *testing.T) {
	for _, thread := range []string{"t1", "../../outside", "0123456789ABCDEF0123456789abcdef"} {
		b := goodBody(t)
		b.Thread = thread
		if err := b.Validate(); err == nil {
			t.Errorf("thread %q was accepted", thread)
		} else if !strings.Contains(err.Error(), "thread is not a message id") {
			t.Errorf("thread %q: %v, want the sentence naming the shape", thread, err)
		}
	}
	b := goodBody(t)
	b.InReplyTo = "../x"
	if err := b.Validate(); err == nil || !strings.Contains(err.Error(), "in_reply_to is not a message id") {
		t.Errorf("in_reply_to ../x: %v", err)
	}
	b.InReplyTo = "fedcba9876543210fedcba9876543210"
	if err := b.Validate(); err != nil {
		t.Errorf("a reply naming a message id was refused: %v", err)
	}
	b.InReplyTo = ""
	if err := b.Validate(); err != nil {
		t.Errorf("an empty in_reply_to was refused: %v", err)
	}
}

// Two attachment names that differ only in case are one file on a disk
// that folds case, so a sender may not ship both, on this path as on the
// stream's: the rule is one, in DistinctAttachmentNames, run by the
// sender's rule. A receiver takes the pair and lets the filesystem say
// whether they are one file, writing the second as x-2 if they are.
func TestASenderMayNotShipNamesThatAreOneFileWhereCaseDoesNotCount(t *testing.T) {
	for _, names := range [][2]string{{"Report.txt", "report.txt"}, {"Makefile", "makefile"}} {
		a, _ := NewAttachment(names[0], []byte("a"))
		b, _ := NewAttachment(names[1], []byte("b"))
		body := Body{Type: TypeNote, Thread: "0123456789abcdef0123456789abcdef", Attachments: []Attachment{a, b}}
		err := ValidAttachmentNames(body.AttachmentNames())
		if err == nil {
			t.Fatalf("the sender's rule took %q beside %q", names[0], names[1])
		}
		if !strings.Contains(err.Error(), "are one file where case does not count") {
			t.Fatalf("%q beside %q: %v, want the sentence naming the rule", names[0], names[1], err)
		}
		if err := body.Validate(); err != nil {
			t.Fatalf("Validate refused %q beside %q, which the write settles: %v", names[0], names[1], err)
		}
	}
	a, _ := NewAttachment("Report.txt", []byte("a"))
	b, _ := NewAttachment("report.md", []byte("b"))
	if err := ValidAttachmentNames([]string{a.Name, b.Name}); err != nil {
		t.Fatalf("two names that are two files were refused: %v", err)
	}
}

// A subject is one line and free text is prose: neither may carry what a
// terminal would obey rather than show. The table is what a message may
// say about itself, at Body.Validate; the stream package runs the same
// rows through BuildManifest, so both paths refuse the same things. An
// attachment name has two columns: what a receiver takes at Validate (a
// line break, a NUL and a byte that is not UTF-8 refused as for any
// text; the rest made safe at the write), and what a sender may ship.
func TestValidateHoldsSubjectTextAndNamesToWhatATerminalShows(t *testing.T) {
	for _, tc := range freeTextRows() {
		subject := Body{Type: TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Subject: "s" + tc.bytes + "s", Text: "x"}
		if err := subject.Validate(); (err == nil) != tc.inSubject {
			t.Errorf("subject with %s: %v, want accepted=%v", tc.name, err, tc.inSubject)
		}
		text := Body{Type: TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Text: "x" + tc.bytes + "x"}
		if err := text.Validate(); (err == nil) != tc.inText {
			t.Errorf("text with %s: %v, want accepted=%v", tc.name, err, tc.inText)
		}
		data := []byte("d")
		sum := sha256.Sum256(data)
		a := Attachment{Name: "n" + tc.bytes + "n", Media: DefaultMedia, Size: 1, SHA256: hex.EncodeToString(sum[:]), Data: data}
		named := Body{Type: TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Text: "x", Attachments: []Attachment{a}}
		if err := named.Validate(); (err == nil) != tc.inName {
			t.Errorf("attachment name with %s: %v, want accepted=%v", tc.name, err, tc.inName)
		}
		if err := ValidAttachmentNames([]string{a.Name}); (err == nil) != tc.shipped {
			t.Errorf("attachment name with %s at the sender: %v, want shipped=%v", tc.name, err, tc.shipped)
		}
	}
	// The refusal names the character and its kind, and for a subject
	// says the rule.
	err := (&Body{Type: TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Subject: "two\nlines", Text: "x"}).Validate()
	if err == nil || !strings.Contains(err.Error(), "U+000A, a control character; a subject is one line") {
		t.Errorf("a two-line subject: %v", err)
	}
	err = (&Body{Type: TypeAsk, Thread: "0123456789abcdef0123456789abcdef", Text: "run\x1b[2K"}).Validate()
	if err == nil || !strings.Contains(err.Error(), "text contains U+001B, a control character") {
		t.Errorf("an escape in the text: %v", err)
	}
}

// freeTextRow is one thing a sender might put in a subject, a text or an
// attachment name, and where it is allowed: inName is what a receiver
// takes at Validate, shipped what a sender may send.
type freeTextRow struct {
	name, bytes                        string
	inSubject, inText, inName, shipped bool
}

// freeTextRows is the table both Validates are held to; the stream
// package's test carries the same rows as a literal, since a test cannot
// import another's.
func freeTextRows() []freeTextRow {
	return []freeTextRow{
		{"an escape", "\x1b[2K", false, false, true, false},
		{"a carriage return", "\r", false, false, false, false},
		{"a bidi override", "\u202e", false, false, true, false},
		{"a private-use rune", "\ue000", false, false, true, false},
		{"a line separator", "\u2028", false, false, true, false},
		{"a newline", "\n", false, true, false, false},
		{"a tab", "\t", false, true, true, false},
		{"a byte that is not UTF-8", "\xff", false, false, false, false},
		{"plain prose", "hello, world", true, true, true, true},
		{"letters beyond ASCII", "café 中文", true, true, true, true},
	}
}

// An attachment name is a file name on Windows too, since the receiver
// may be there and a sender cannot know where a message lands: a stem
// that is a device name opens the device rather than a file, and a
// trailing dot or space is stripped, so two names collide. The table is
// what a sender may ship, at ValidAttachmentName, each refusal saying it
// holds for every receiver; the stream package runs the same rows
// through BuildManifest. A receiver takes every row and writes the file
// under SafeName of it, which TestLimitSafeNameIsAFixedPoint pins.
func TestAnAttachmentNameIsAFileNameOnWindowsToo(t *testing.T) {
	for _, tc := range windowsNameRows() {
		err := ValidAttachmentName(tc.name)
		if (err == nil) != tc.allowed {
			t.Errorf("%q: %v, want accepted=%v", tc.name, err, tc.allowed)
		}
		if err != nil && !strings.Contains(err.Error(), "for every receiver") {
			t.Errorf("%q: %v does not say the rule is for every receiver", tc.name, err)
		}
		if err := ValidAttachmentText(tc.name); err != nil {
			t.Errorf("%q: the receiver refused a name that is the write's to make safe: %v", tc.name, err)
		}
	}
	if err := ValidAttachmentName("nul.txt"); err == nil || !strings.Contains(err.Error(), "NUL is a device name on Windows") {
		t.Errorf("nul.txt: %v, want the device named", err)
	}
	if err := ValidAttachmentName("report.txt."); err == nil || !strings.Contains(err.Error(), "ends in a dot or a space, which Windows strips") {
		t.Errorf("report.txt.: %v, want the trailing rule named", err)
	}
}

// windowsNameRow is one attachment name and whether Windows would make a
// file of it.
type windowsNameRow struct {
	name    string
	allowed bool
}

// windowsNameRows is the table both Validates are held to; the stream
// package's test carries the same rows as a literal.
func windowsNameRows() []windowsNameRow {
	return []windowsNameRow{
		{"CON", false},
		{"con", false},
		{"con.txt", false},
		{"Con.tar.gz", false},
		{"COM1", false},
		{"com9.log", false},
		{"LPT1", false},
		{"lpt0", false},
		{"COM0", false},
		{"COM\u00b9", false},
		{"lpt\u00b3", false},
		{"COM10", true},
		{"nul", false},
		{"aux.", false},
		{"report.txt.", false},
		{"report.txt ", false},
		{".hidden", false},
		{"console.txt", true},
		{"CONIN$", false},
		{"conout$.txt", false},
		{"conin", true},
		{"CON .txt", false},
		{"a<b.txt", false},
		{"a>b.txt", false},
		{"a\"b.txt", false},
		{"a|b.txt", false},
		{"a?b.txt", false},
		{"a*b.txt", false},
		{"a'b.txt", true},
		{"prn", false},
		{"PRN.dat", false},
		{"report.txt", true},
		{"comet.md", true},
	}
}

// A note from the string review, kept as a test a reader can run: on the
// wire a Body arrives as JSON, and encoding/json replaces every invalid
// byte in a string with U+FFFD as it decodes, so the UTF-8 branch of the
// three rules never fires on the envelope path or the stream path; the
// replacement is a printable character and the signature covered the raw
// bytes, so nothing is wrong downstream, but the rule is vacuous there.
func TestInvalidUTF8OnTheWireIsReplacedNotRefused(t *testing.T) {
	raw := []byte("{\"type\":\"note\",\"thread\":\"00000000000000000000000000000000\",\"subject\":\"a\xffb\",\"text\":\"c\xfed\"," +
		"\"attachments\":[{\"name\":\"n\xffm\",\"media\":\"text/plain\",\"size\":0,\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"data\":\"\"}]}")
	var b Body
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !utf8.ValidString(b.Subject) || !utf8.ValidString(b.Text) || !utf8.ValidString(b.Attachments[0].Name) {
		t.Fatalf("the decoder kept an invalid byte: subject %q text %q name %q", b.Subject, b.Text, b.Attachments[0].Name)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("a wire body with 0xff in three fields was refused after decoding: %v", err)
	}
	if b.Subject != "a\ufffdb" || b.Attachments[0].Name != "n\ufffdm" {
		t.Fatalf("subject %q name %q: expected U+FFFD where 0xff was", b.Subject, b.Attachments[0].Name)
	}
}

// TestTheWindowsCharactersAreRefusedInNamesAlone: the seven characters
// Windows forbids in a file name are a rule for an attachment's name and
// not for a subject or a text, which are prose.
func TestTheWindowsCharactersAreRefusedInNamesAlone(t *testing.T) {
	for _, prose := range []string{"what's new?", `say "hi"`, "a | b", "<b>", "2 * 3", "a: b"} {
		if err := ValidSubject(prose); err != nil {
			t.Errorf("ValidSubject refused %q: %v", prose, err)
		}
		if err := ValidText(prose); err != nil {
			t.Errorf("ValidText refused %q: %v", prose, err)
		}
	}
}
