# Agent guide

Read [VISION.md](VISION.md) before a change that adds a rule, a taint source, a transport, or a control-plane seam. It says what the proxy is for, what it refuses to be, and how to judge whether a change fits.

[README.md](README.md) holds the install steps, the architecture, the policy format, the audit format, and the verification tiers.

## Before a change is done

Every command under "Development" in the README must exit 0. After a change under `src`, `specs`, `tests`, `scripts`, `policies`, or `fixtures`, or to `Cargo.toml` or `Cargo.lock`, run the `verify-taint-invariants` skill in `.claude/skills/verify-taint-invariants/SKILL.md`. It proves the checks still catch a deliberate break and tells you when to move the sync commit.

## Rules that are not in the code

- No source or test file may open a network connection. The README's last development command greps for it.
- A new rule or taint source gets a replay scenario in `fixtures/replay-corpus.json` and a row in the README policy tables.
- Audit lines are the only record of a decision. A change to their fields or to redaction updates the README "Audit log" section in the same commit.
