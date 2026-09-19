package kit

import (
	"strings"
	"testing"
)

// TestLimitListenPort: the port in a listen address is within [1, 65535],
// read as text: zero, one over, a negative, the text one past the type's
// maximum, a sign inside the digits, a leading space and a digit outside
// ASCII are each refused naming the address, and one, the ceiling and a
// leading plus are taken.
func TestLimitListenPort(t *testing.T) {
	for _, port := range []string{"0", "65536", "-1", "9223372036854775808", "1-2", " 1", "\u0661", "", "https"} {
		listen := ":" + port
		if _, err := listenPort(listen); err == nil || !strings.Contains(err.Error(), `not "`+listen+`"`) {
			t.Errorf("listen %q: %v; want the refusal naming it", listen, err)
		}
	}
	for _, tc := range []struct {
		port string
		want int
	}{{"1", 1}, {"+1", 1}, {"65535", 65535}, {"9443", 9443}} {
		got, err := listenPort(":" + tc.port)
		if err != nil || got != tc.want {
			t.Errorf("listen %q: %d %v; want %d", ":"+tc.port, got, err, tc.want)
		}
	}
}
