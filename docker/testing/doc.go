// Package e2e is the container suite: the deployment guide and the enrolling
// guide run in four containers, followed by a matrix of what goes wrong in
// the wild, with a report of what every party saw.
//
// The test files carry the e2e build tag, so go test ./... never starts a
// container; make e2e does, through run.sh in this directory, which builds
// the image, brings the stack up, runs the tests and takes it down again.
// This file exists so the package is visible to vet and build without the
// tag.
package e2e
