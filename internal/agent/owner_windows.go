package agent

import "os"

// ownedByMe cannot be answered from a FileInfo on Windows; %LOCALAPPDATA%
// is the user's own by construction, and that is what is relied on.
func ownedByMe(os.FileInfo) bool { return true }
