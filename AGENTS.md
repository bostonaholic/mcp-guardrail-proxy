# Agent guide

Read [VISION.md](VISION.md) before a change that adds a rule, a taint source, a transport, or a control-plane seam. It says what the proxy is for, what it refuses to be, and how to judge whether a change fits.

[INSTALL.md](INSTALL.md) holds the install steps. [README.md](README.md) holds the architecture, the policy format, the audit format, and the verification tiers.

To release a new version, use the `release-new-version` skill in `.claude/skills/release-new-version/SKILL.md`.

## Before a change is done

Every command under "Development" in the README must exit 0. After a change under `src`, `specs`, `tests`, `scripts`, `policies`, or `fixtures`, or to `Cargo.toml` or `Cargo.lock`, run the `verify-taint-invariants` skill in `.claude/skills/verify-taint-invariants/SKILL.md`. It proves the checks still catch a deliberate break and tells you when to move the sync commit.

A pull request with a manual or pre-merge step is not ready until an agent has run that step. Use the `verify-manual-steps` skill in `.claude/skills/verify-manual-steps/SKILL.md`. It drives the desktop app window in a sandbox and checks off each item only on observed evidence. Write a manual step into a PR only when that skill has no driver for it, and say why.

## Rules that are not in the code

- No proxy source or test file (`src`, `tests`) may open a network connection. In the desktop app, only `desktop/src/updater.rs` may. The README's last two development commands grep for both.
- A new rule or taint source gets a replay scenario in `fixtures/replay-corpus.json` and a row in the README policy tables.
- New code that remembers state between events and acts on it gets a pure machine, a spec, and a graph walk. [specs/README.md](specs/README.md) has the steps.
- `desktop/src/clients.rs` and `desktop/src/servers.rs` mirror `INSTALL.md` step 5.2, step 6, and the client reference. A change to one side changes the other in the same commit.
- Audit lines are the only record of a decision. A change to their fields or to redaction updates the README "Audit log" section in the same commit.
