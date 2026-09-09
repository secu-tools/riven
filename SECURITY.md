# Security policy

## Status

Riven is in a testing phase and has not had a stable release. The piece format
may still change. Do not use it as the only copy of anything you cannot lose.

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button on the
Security tab, which opens a draft advisory visible only to the maintainer. Please
do not open a public issue for a vulnerability.

Useful in a report: what an attacker starts with (a piece? a password? a key
file? just an image?), what they end up with, and the smallest input that shows
it. A patch is welcome but not required.

## What is in scope

Anything that breaks one of these, which is what the tool claims:

- Fewer than K pieces reveal the content, at any computational cost.
- K pieces without every password and recipient private key reveal the content.
- A modified piece opens rather than failing, for a set with a password layer.
- A file supplied as a piece causes a panic, an unbounded allocation, or writes
  outside the working directory.
- A secret reaches disk, a log, the process list, or another user.

## Known limitations, already documented

These are design consequences rather than bugs. They are listed so a report can
skip them, and each is written up in full where it is linked.

- **Keyless mode** (`--keyless`) seals its envelope with a published key, so a
  piece's metadata is readable without a password. That is intended: it is what
  identifies a stray piece. The content stays covered by the threshold. Nothing
  authenticates such a set, and that cannot be fixed within the mode -- a key
  built into Riven would be in every binary.
- **Recipient-only sets** (no password layer) have the same public envelope, and
  HPKE base mode gives no sender authentication.
- **Only passwords are pinned in memory.** Derived keys, plaintext and shares
  are zeroed when done with but not locked, because they are unbounded in size,
  so they can reach swap.
- **The Argon2 cost byte is not authenticated** before it is used, so a piece of
  unknown origin can ask for an expensive open. The cost is bounded by the
  strongest setting Riven itself offers.
- `--text` puts the secret in the process list; `--text-env` avoids that.
- Windows ignores POSIX file modes; access is governed by inherited ACLs.

