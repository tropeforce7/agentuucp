package message

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
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

func TestValidateRejectsBadAttachmentNames(t *testing.T) {
	data := []byte("x")
	sum := sha256.Sum256(data)
	for _, name := range []string{"", "..", ".", "a/b", "../x", "..\\x", "dir/../x", strings.Repeat("n", 256)} {
		a := Attachment{Name: name, Media: DefaultMedia, Size: 1, SHA256: hex.EncodeToString(sum[:]), Data: data}
		b := Body{Type: TypeNote, Thread: "0123456789abcdef0123456789abcdef", Attachments: []Attachment{a}}
		if err := b.Validate(); err == nil {
			t.Fatalf("accepted attachment name %q", name)
		}
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

func TestValidateRejectsDuplicateNames(t *testing.T) {
	a, _ := NewAttachment("x.txt", []byte("a"))
	b := Body{Type: TypeNote, Thread: "0123456789abcdef0123456789abcdef", Attachments: []Attachment{a, a}}
	if err := b.Validate(); err == nil {
		t.Fatal("accepted duplicate attachment names")
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
// that folds case, so a message may not carry both, on this path as on the
// stream's: the rule is one, in DistinctAttachmentNames.
func TestValidateRejectsNamesThatAreOneFileWhereCaseDoesNotCount(t *testing.T) {
	for _, names := range [][2]string{{"Report.txt", "report.txt"}, {"Makefile", "makefile"}} {
		a, _ := NewAttachment(names[0], []byte("a"))
		b, _ := NewAttachment(names[1], []byte("b"))
		body := Body{Type: TypeNote, Thread: "0123456789abcdef0123456789abcdef", Attachments: []Attachment{a, b}}
		err := body.Validate()
		if err == nil {
			t.Fatalf("accepted %q beside %q", names[0], names[1])
		}
		if !strings.Contains(err.Error(), "are one file where case does not count") {
			t.Fatalf("%q beside %q: %v, want the sentence naming the rule", names[0], names[1], err)
		}
	}
	a, _ := NewAttachment("Report.txt", []byte("a"))
	b, _ := NewAttachment("report.md", []byte("b"))
	if err := (&Body{Type: TypeNote, Thread: "0123456789abcdef0123456789abcdef", Attachments: []Attachment{a, b}}).Validate(); err != nil {
		t.Fatalf("two names that are two files were refused: %v", err)
	}
}
