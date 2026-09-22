package message

import (
	"strings"
	"testing"
)

const knockThread = "0123456789abcdef0123456789abcdef"

func goodKnock() Body {
	return Body{Type: TypeKnock, Thread: knockThread, Name: "alice", Text: "alice would like to exchange keys"}
}

// A knock is held to its shape at Validate, on both ends, and at
// ValidShape, which Load runs on a record read back: no subject, no
// in_reply_to, no attachment, the knocker's name present and under the
// name rule, the text at most MaxKnockText bytes and one line without a
// tab; and a name on any other type is refused, since a peer's name is the
// peer list's. Each refusal names what it refuses.
func TestAKnockIsHeldToItsShape(t *testing.T) {
	both := func(b Body) (validate, shape error) { return b.Validate(), b.ValidShape() }
	if v, s := both(goodKnock()); v != nil || s != nil {
		t.Fatalf("a good knock: Validate %v, ValidShape %v", v, s)
	}
	a, err := NewAttachment("a.txt", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(b *Body)
		want string
	}{
		{"a subject", func(b *Body) { b.Subject = "hi" }, "a knock has no subject"},
		{"an in_reply_to", func(b *Body) { b.InReplyTo = knockThread }, "a knock opens a thread and answers nothing"},
		{"an attachment", func(b *Body) { b.Attachments = []Attachment{a} }, "a knock carries no attachment"},
		{"no name", func(b *Body) { b.Name = "" }, "a knock carries the knocker's name"},
		{"a name that is not one", func(b *Body) { b.Name = "not a name" }, "a knock's name: name \"not a name\""},
		{"the reserved name", func(b *Body) { b.Name = "self" }, "a knock's name: the name \"self\" is reserved"},
		{"a name too long", func(b *Body) { b.Name = strings.Repeat("a", 65) }, "a knock's name: name is 65 bytes; at most 64"},
		{"a text one over", func(b *Body) { b.Text = strings.Repeat("t", MaxKnockText+1) }, "a knock's text is 513 bytes; at most 512"},
		{"a newline", func(b *Body) { b.Text = "two\nlines" }, "a knock's text is one line, without a tab"},
		{"a tab", func(b *Body) { b.Text = "a\tb" }, "a knock's text is one line, without a tab"},
		{"no thread", func(b *Body) { b.Thread = "" }, "thread is required"},
	} {
		b := goodKnock()
		tc.edit(&b)
		v, s := both(b)
		if v == nil || !strings.Contains(v.Error(), tc.want) {
			t.Errorf("%s at Validate: %v; want %q", tc.name, v, tc.want)
		}
		if s == nil || !strings.Contains(s.Error(), tc.want) {
			t.Errorf("%s at ValidShape: %v; want %q", tc.name, s, tc.want)
		}
	}
	// The edges taken: a text at the cap, a name at its cap, an empty text.
	for _, tc := range []struct {
		name string
		edit func(b *Body)
	}{
		{"a text at the cap", func(b *Body) { b.Text = strings.Repeat("t", MaxKnockText) }},
		{"a name at its cap", func(b *Body) { b.Name = strings.Repeat("a", 64) }},
		{"an empty text", func(b *Body) { b.Text = "" }},
	} {
		b := goodKnock()
		tc.edit(&b)
		if v, s := both(b); v != nil || s != nil {
			t.Errorf("%s: Validate %v, ValidShape %v; want taken", tc.name, v, s)
		}
	}
	// A carriage return is refused by the text rule every message meets,
	// before the knock's line rule, and the sentence is that rule's.
	b := goodKnock()
	b.Text = "a\rb"
	if err := b.Validate(); err == nil || !strings.Contains(err.Error(), "text contains U+000D, a control character") {
		t.Errorf("a carriage return: %v", err)
	}
	// A name on every other type is refused.
	for _, typ := range []string{TypeAsk, TypeReply, TypeNote, TypeAck} {
		b := Body{Type: typ, Thread: knockThread, Text: "x", Name: "alice"}
		if typ == TypeReply {
			b.InReplyTo = knockThread
		}
		v, s := both(b)
		if v == nil || !strings.Contains(v.Error(), "name is a knock's alone") {
			t.Errorf("a name on %s at Validate: %v", typ, v)
		}
		if s == nil || !strings.Contains(s.Error(), "name is a knock's alone") {
			t.Errorf("a name on %s at ValidShape: %v", typ, s)
		}
	}
	if !ValidType(TypeKnock) {
		t.Error("knock is not a type")
	}
}

// The knock text's table: everything a terminal would obey rather than
// show, and the line and the tab that an ordinary text keeps, each refused
// for a knock at Validate and at ValidShape; prose taken. The bytes that
// are not UTF-8 are refused at the byte level, before any rune is read.
func TestAKnocksTextIsOneLineATerminalShows(t *testing.T) {
	for _, tc := range []struct {
		name, bytes string
		taken       bool
	}{
		{"an escape", "\x1b[2K", false},
		{"a carriage return", "\r", false},
		{"a bidi override", "‮", false},
		{"a zero-width joiner", "‍", false},
		{"a private-use rune", "", false},
		{"a line separator", " ", false},
		{"a next line", "\u0085", false},
		{"a newline", "\n", false},
		{"a tab", "\t", false},
		{"a byte that is not UTF-8", "\xff", false},
		{"plain prose", "hello, world", true},
		{"letters beyond ASCII", "café 中文", true},
	} {
		b := goodKnock()
		b.Text = "x" + tc.bytes + "x"
		if err := b.Validate(); (err == nil) != tc.taken {
			t.Errorf("a knock's text with %s at Validate: %v, want taken=%v", tc.name, err, tc.taken)
		}
		if err := b.ValidShape(); (err == nil) != tc.taken {
			t.Errorf("a knock's text with %s at ValidShape: %v, want taken=%v", tc.name, err, tc.taken)
		}
	}
}
