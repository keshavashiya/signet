# Security Policy

Signet is **alpha and unaudited**. Do not rely on it where being wrong has
consequences.

## Reporting a vulnerability

Do not open a public issue.

Use GitHub's private reporting — **[Report a
vulnerability](https://github.com/keshavashiya/signet/security/advisories/new)**,
or the Security tab of this repository. The report stays private to you and the
maintainer until there is a fix to publish.

Include what you would want to receive: what you attacked, what you got, and
the shortest reproduction you have. Expect an acknowledgement within a week.
There is no bounty.

## What counts

Anything that lets an attacker forge, replay, or alter a frame that a receiver
then accepts as authentic — that is the one property this protocol exists to
provide. Also in scope: a parser that panics on untrusted input, since on a
radio that is a remote denial of service against a device someone is relying
on, and rule 5 of the hard rules says it must not happen.

## What belongs in public

Attacks on the *design* rather than an implementation bug. `PROTOCOL.md` is
published precisely so it can be attacked on paper before anyone trusts it in
the field — open a normal issue. Known gaps are already tracked in
[`docs/src/protocol/threat-model.md`](docs/src/protocol/threat-model.md),
including the one where a public randomness beacon's own signature is not
post-quantum.

## Supported versions

Before v1.0.0 only `main` is supported, and the wire format may change without
a compatibility path. Pin a commit.
