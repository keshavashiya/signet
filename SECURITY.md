# Security Policy

Signet is **alpha and unaudited**. Do not rely on it where being wrong has
consequences.

## Reporting a vulnerability

Do not open a public issue.

Use GitHub's private reporting: **[Report a
vulnerability](https://github.com/keshavashiya/signet/security/advisories/new)**,
or the Security tab of this repository. The report stays private to you and the
maintainer until there is a fix to publish.

Include what you would want to receive: what you attacked, what you got, and
the shortest reproduction you have. Expect an acknowledgement within a week.
There is no bounty.

## What counts

Anything that lets an attacker forge, replay or alter a frame that a receiver
then accepts as authentic, since that is the property this protocol exists to
provide. Also in scope: a parser that panics on untrusted input. On a radio
that is a remote denial of service against a device someone relies on, and
hard rule 5 forbids it.

## What belongs in public

Attacks on the *design* rather than an implementation bug. `PROTOCOL.md` is
published so it can be reviewed before anyone uses it in the field, so open a
normal issue. Known gaps are listed in
[`docs/src/protocol/threat-model.md`](docs/src/protocol/threat-model.md) and
[PROTOCOL.md §14](PROTOCOL.md#14-open-questions).

## Supported versions

Before v1.0.0 only `main` is supported, and the wire format may change without
a compatibility path. Pin a commit.
