<!-- Thanks for the PR! Fill in the sections below. Delete anything that doesn't apply. -->

## Summary

<!-- One or two sentences: what changes and why. -->

## Linked issues

<!-- e.g. Closes #123, Refs #456. Required for anything touching the wire
     format or the security model. -->

## Changes

<!-- Bulleted list. Focus on observable behaviour and public APIs. -->

-

## Testing

<!-- How you verified this. Include relevant `cargo test` output or a
     `signet sim` run if the change affects the model. -->

-

## Checklist

- [ ] No [hard rule](../CONTRIBUTING.md#hard-rules) broken
- [ ] `just ci` clean (fmt + clippy + no_std + tests)
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (or this is a no-op for users)
- [ ] `PROTOCOL.md` updated **in this PR** if anything changed on the wire
- [ ] New rejection paths have tests
- [ ] No new dependency in `signet-core` (or: justified below)
- [ ] Phases referred to by name (hard rule 9)

## Security impact

<!-- Required if this touches crates/core, PROTOCOL.md, or anything that parses
     radio input. State "none" explicitly if there is none — do not delete
     this section. -->
