//go:build race

package client

// raceEnabled says the race detector is on, whose instrumentation inflates
// what a test measures of allocation.
const raceEnabled = true
