// Package fileopens is the file-open ledger: one row in ledger.txt for
// every call in the non-test tree that opens, makes, removes, renames,
// walks, lists or runs something by a path, saying where that path came
// from. Nothing imports it; its test is what it is for. The rule it keeps
// is the maintainer's: for every file operation the path's provenance is fully
// accounted for, and a path not generated locally is checked for traversal
// from malicious input, by a named rule at a named point.
package fileopens
