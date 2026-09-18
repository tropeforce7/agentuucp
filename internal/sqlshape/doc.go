// Package sqlshape holds one test: that the text of every SQL query in the
// tree is a constant, so that a value reaches the database only as a
// parameter. Nothing imports it. The rule it keeps is the maintainer's: every use of
// SQL passes values as parameters; the test is the mechanism that finds a
// query built from a value before it is a finding.
package sqlshape
