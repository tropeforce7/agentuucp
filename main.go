// Command agentuucp is the client under its full name. It is the same program
// as auu, and this package exists at the module root for one reason: Go names
// an installed binary after the last element of its import path, so
//
//	go install github.com/tropeforce7/agentuucp@latest
//
// can only ever produce something called agentuucp, and a module root with no
// main package gives it nothing to produce at all. Everything else about the
// program, including what it calls itself in its own advice, is in
// internal/auu.
package main

import "github.com/tropeforce7/agentuucp/internal/auu"

func main() { auu.Main("agentuucp") }
