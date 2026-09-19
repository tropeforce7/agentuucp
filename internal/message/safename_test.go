package message

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestLimitSafeNameIsAFixedPoint pins every step of SafeName by example
// and proves the rule the sender is held to: for every name in the
// table, SafeName of SafeName is SafeName (a fixed point), the sender's
// rule takes SafeName's output, and the sender's rule takes the name
// itself exactly when SafeName would leave it alone. The table is every
// step's example, the traversal set, the device names, the seven Windows
// characters, a leading dot, 300 bytes with and without an extension, a
// multibyte rune at the cut, `.`, `..` and the empty string.
func TestLimitSafeNameIsAFixedPoint(t *testing.T) {
	long := strings.Repeat("a", 300)
	// 150 two-byte runes, 300 bytes: the cut at 200 falls on a rune
	// boundary here, and at 198 for the extension row it does not, so the
	// cut must step back.
	multibyte := strings.Repeat("é", 150)
	// The second reader's inputs: spaces before the cut that the cut then
	// trims to a device stem, to nothing but the extension, or to a name
	// beginning with a dot; each settles in a second pass.
	spaces := func(n int) string { return strings.Repeat(" ", n) }
	rows := []struct{ in, want string }{
		// Step 1: the base on either separator.
		{"report.txt", "report.txt"},
		{"a/b/report.txt", "report.txt"},
		{`C:\Users\x\report.txt`, "report.txt"},
		{"../x", "x"},
		{"x/../../y", "y"},
		{"/etc/passwd", "passwd"},
		{`..\x`, "x"},
		{`C:\x`, "x"},
		{"a/b", "b"},
		{"dir/", "attachment"},
		// Step 2: forbidden runes, invalid bytes and the seven characters.
		{"a<b>.txt", "a_b_.txt"},
		{`say "hi".txt`, "say _hi_.txt"},
		{"a|b?c*d.txt", "a_b_c_d.txt"},
		{"C:x", "C_x"},
		{"file\x1b[2K.txt", "file_[2K.txt"},
		{"bidi\u202e.txt", "bidi_.txt"},
		{"tab\there.txt", "tab_here.txt"},
		{"two\nlines.txt", "two_lines.txt"},
		{"nul\x00.txt", "nul_.txt"},
		{"bad\xffbyte.txt", "bad_byte.txt"},
		{"private\ue000.txt", "private_.txt"},
		// Step 3: trailing dots and spaces, a leading dot.
		{"report.txt.", "report.txt"},
		{"report.txt ", "report.txt"},
		{"report.txt. . .", "report.txt"},
		{".bashrc", "_bashrc"},
		{".hidden.txt", "_hidden.txt"},
		{"..x", "_.x"},
		// Step 4: a device stem.
		{"CON", "_CON"},
		{"con.txt", "_con.txt"},
		{"com1.txt", "_com1.txt"},
		{"LPT\u00b9", "_LPT\u00b9"},
		{"CONIN$", "_CONIN$"},
		{"nul", "_nul"},
		{"CON .txt", "_CON .txt"},
		{"console.txt", "console.txt"},
		{"com10.log", "com10.log"},
		// Step 5: the cut.
		{long, long[:200]},
		{long + ".txt", long[:196] + ".txt"},
		{long + "." + strings.Repeat("x", 30), (long + "." + strings.Repeat("x", 30))[:200]},
		{multibyte, strings.Repeat("é", 100)},
		{multibyte + ".md", strings.Repeat("é", 98) + ".md"},
		{strings.Repeat("a", 199) + ". .txt", strings.Repeat("a", 196) + ".txt"},
		// The pass run again: what the cut leaves is taken by the steps
		// before it.
		{"CON" + spaces(193) + "x.txt", "_CON.txt"},
		{"CON" + spaces(197) + "x", "_CON"},
		{"NUL" + spaces(197) + "x", "_NUL"},
		{spaces(196) + ".bashrc", "_bashrc"},
		{spaces(197) + "CON.txt", "_txt"},
		{"x." + strings.Repeat("a", 198), "x." + strings.Repeat("a", 198)},
		// Step 6: nothing left.
		{"", "attachment"},
		{".", "attachment"},
		{"..", "attachment"},
		{"...", "attachment"},
		{" ", "attachment"},
		{"/", "attachment"},
		{"\x00", "_"},
		// And ordinary names, which are fixed points.
		{"Report.txt", "Report.txt"},
		{"café 中文.md", "café 中文.md"},
		{"a'b.txt", "a'b.txt"},
		{"a b.txt", "a b.txt"},
		{"archive.tar.gz", "archive.tar.gz"},
		{"README", "README"},
	}
	for _, r := range rows {
		got := SafeName(r.in)
		if got != r.want {
			t.Errorf("SafeName(%q) = %q, want %q", r.in, got, r.want)
		}
		if again := SafeName(got); again != got {
			t.Errorf("SafeName(%q) = %q is not a fixed point: SafeName of it is %q", r.in, got, again)
		}
		if err := ValidAttachmentName(got); err != nil {
			t.Errorf("the sender's rule refuses SafeName(%q) = %q: %v", r.in, got, err)
		}
		if fixed := got == r.in; (ValidAttachmentName(r.in) == nil) != fixed {
			t.Errorf("ValidAttachmentName(%q) = %v, but SafeName leaves it alone: %v", r.in, ValidAttachmentName(r.in), fixed)
		}
		if len(got) > SafeNameMaxBytes || !utf8.ValidString(got) || strings.ContainsAny(got, `/\`) {
			t.Errorf("SafeName(%q) = %q is over the cap, not UTF-8, or has a separator", r.in, got)
		}
	}
	// And a sweep across the cut: names of every length from 190 to 260
	// bytes built of a stem, then dots and spaces, then a device stem, a
	// dot and letters, so that the cut lands on each kind of byte in
	// turn; every output is a fixed point the sender's rule takes.
	for n := 190; n <= 260; n++ {
		for _, tail := range []string{" .CON.txt", ". .bashrc", "   NUL", "..x", "  ", "é.txt"} {
			pad := n - len(tail)
			if pad < 0 {
				continue
			}
			in := strings.Repeat("a", pad/2) + strings.Repeat(" ", pad-pad/2) + tail
			got := SafeName(in)
			if SafeName(got) != got || ValidAttachmentName(got) != nil {
				t.Errorf("SafeName(%q) = %q is not a fixed point the sender's rule takes: %v", in, got, ValidAttachmentName(got))
			}
			for _, k := range []int{2, 10, 1000} {
				if num := Numbered(got, k); ValidAttachmentName(num) != nil || len(num) > SafeNameMaxBytes {
					t.Errorf("Numbered(%q, %d) = %q is not a name the sender's rule takes", got, k, num)
				}
			}
		}
	}
	// The sentence names the step for the sender.
	for _, tc := range []struct{ name, says string }{
		{"a/b", "path separator"},
		{"a<b", "Windows forbids"},
		{"file\x1b.txt", "control character"},
		{"report.txt.", "Windows strips"},
		{".bashrc", "begins with a dot"},
		{"con.txt", "device name on Windows"},
		{long, "over 200"},
		{"", "empty name"},
		{"bad\xff", "not valid UTF-8"},
	} {
		if err := ValidAttachmentName(tc.name); err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("ValidAttachmentName(%q) = %v; want the step, %q", tc.name, err, tc.says)
		}
	}
}

// TestLimitNumberedNamesAreSafeNames: the unique loop's candidates keep
// the extension, put the number before it, stay within the cap, and are
// names the sender's rule takes, so a receiver never writes under a name
// it would not accept from a sender.
func TestLimitNumberedNamesAreSafeNames(t *testing.T) {
	long := strings.Repeat("a", 196) + ".txt"
	for _, tc := range []struct {
		safe string
		n    int
		want string
	}{
		{"x.txt", 1, "x.txt"},
		{"x.txt", 2, "x-2.txt"},
		{"x.txt", 1000, "x-1000.txt"},
		{"a.tar.gz", 3, "a.tar-3.gz"},
		{"README", 2, "README-2"},
		{"_bashrc", 2, "_bashrc-2"},
		{"attachment", 7, "attachment-7"},
		{long, 2, strings.Repeat("a", 194) + "-2.txt"},
		{strings.Repeat("é", 100), 2, strings.Repeat("é", 99) + "-2"},
		// The second reader's name: a 200-byte safe name whose extension
		// is 199 bytes, which the first draft cut to a negative budget and
		// panicked on; the extension is not one, and the suffix goes at
		// the end within the cap.
		{"x." + strings.Repeat("a", 198), 2, "x." + strings.Repeat("a", 196) + "-2"},
		{"x." + strings.Repeat("a", 198), 1000, "x." + strings.Repeat("a", 193) + "-1000"},
	} {
		got := Numbered(tc.safe, tc.n)
		if got != tc.want {
			t.Errorf("Numbered(%q, %d) = %q, want %q", tc.safe, tc.n, got, tc.want)
		}
		if err := ValidAttachmentName(got); err != nil {
			t.Errorf("Numbered(%q, %d) = %q is not a name the sender's rule takes: %v", tc.safe, tc.n, got, err)
		}
	}
}
