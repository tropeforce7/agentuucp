// Package limits is the limit ledger: one row in ledger.txt for every
// place in the non-test tree where an integer from outside enters the
// program — a field of integer or duration type in a struct with a json
// tag, a strconv.Atoi or strconv.Parse*, a binary.*.Uint* read, an
// integer or duration flag — saying the range the code holds it to, or
// that it is open, and naming the TestLimit test that takes it to the
// edge and one step past. Nothing imports it; its test is what it is for.
// The rule it keeps is the maintainer's: every integer from outside is tested one
// before, one after, and at its type's minimum and maximum, an open one
// refuses a negative with an error, and the test is written down beside
// the site, so that a site with no test is found before it is a fault.
//
// The walk is over the non-test tree, and a row may say a struct is
// output, written and never decoded, only when no json.Unmarshal or
// Decoder.Decode outside a test reaches its type. A test that round-trips
// a --json view through json.Unmarshal to read what the command printed
// is the test reading, not the program decoding, and does not make the
// view an input.
package limits
