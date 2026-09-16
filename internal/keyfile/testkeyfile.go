package keyfile

// TestPassphrase is a passphrase whose derivation costs are turned down to
// the least each function allows, for tests.
//
// The defaults are three passes over 64 MiB and 600,000 rounds of PBKDF2 on
// purpose, and a test suite that paid them would spend minutes deriving keys
// nobody is attacking. Every cost is recorded in the file, so a file written
// this way still opens and a file written properly still opens here; what a
// test must not do is assert a default by writing one of these.
//
// It lives in the package rather than a test file because the packages that
// build a whole authority for a test need it too.
func TestPassphrase(secret string) Passphrase {
	return Passphrase{
		Secret:     []byte(secret),
		Time:       MinTime,
		Memory:     8 * MinThreads,
		Threads:    MinThreads,
		Iterations: MinIterations,
	}
}
