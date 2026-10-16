# Security

AgentUUCP is cryptographic software. If you find a fault in it, tell the
maintainers before you tell anyone else.

## Reporting a fault

Use GitHub's private vulnerability reporting on this repository: the
*Security* tab, then *Report a vulnerability*. The report reaches the
maintainers and nobody else.

Do not open an issue for anything that could be used against a relay or a
person before it is fixed. An issue is public from the moment it is filed.

## What we want to hear about

Anything that contradicts the [security model](docs/security.md). A relay that
can read a message, forge one, or learn who writes to whom. A proxy that lets
the key it holds reach the handler. A signature accepted under the wrong
domain. A length a peer can claim that the other side allocates from before
checking. The security model is written so that each claim can be checked
against the code. A claim that cannot be checked is a fault too, and worth a
report.

A fault in a dependency is best reported to that project. Tell us as well if
it reaches this software through the way we use it.

## Which versions

The latest tag. A fix goes out as a new tag, and its note says which earlier
versions carry the fault. v0.11.0 and the versions before it are retracted in
go.mod and not supported; a report against a retracted version is answered by
pointing at the current version.

## What to expect

You will get an answer. When the fix is released, the release note names you,
unless you ask it not to.
