---
name: verify-taint-invariants
description: Re-run the MCP guardrail taint invariant checks for the taint, policy, and proxy state machine in src/taint.rs, src/policy.rs, src/proxy.rs and its TLA+ spec specs/McpGuardrailTaint.tla. Run them after any change under src, specs, tests, scripts, policies, or fixtures, or to Cargo.toml or Cargo.lock. Prove that the checks catch a deliberate break before you move the sync commit.
metadata:
  sync-commit: fbc720c67ab6a82ea382ee0101648bf4f80a2d5f
  verified-files: src/taint.rs src/policy.rs src/proxy.rs specs/McpGuardrailTaint.tla
  verified-paths: src specs tests scripts policies fixtures
---

# Verify the MCP guardrail taint invariants

## When to use

Use this skill after you edit any tracked file under `src`, `specs`, `tests`, `scripts`, `policies`, or `fixtures`. Use it also after you edit `Cargo.toml` or `Cargo.lock`.

The sync check under "Check sync status" does not see `Cargo.toml` or `Cargo.lock`. After an edit to either file, run the commands under "Run both verification paths" anyway.

## Check sync status

The sync commit is the last commit on whose tree every command under "Run both verification paths" passed.

Run this command from the repository root:

```sh
git diff --quiet fbc720c67ab6a82ea382ee0101648bf4f80a2d5f -- src specs tests scripts policies fixtures
```

Replace the hash with the value of `metadata.sync-commit` if it has moved. Exit 0 means the verified paths match the sync commit. A non-zero exit means they changed, so run the commands under "Run both verification paths".

The command compares the working tree, so it also sees edits that are not committed. It skips untracked files. Run `git add` on a new file before the check.

## Run both verification paths

Run these three commands in order. Each must exit 0.

1. `MCP_GUARDRAIL_OFFLINE=1 ./scripts/verify-tla.sh`
2. `cargo test`
3. `cargo run -- replay --policy policies/default-policy.toml --corpus fixtures/replay-corpus.json`

The `cargo test` output must also hold this line:

```text
test cli_exits_when_child_exits_with_stdin_open ... ok
```

The custom harness of `tests/integration_test.rs` prints that line. If it is missing, the integration tests did not run.

### What the script reports

The script runs the first available tier only. Its first output line names the tier: `verify-tla: tier <n> (<description>)`.

| Tier | What ran |
|---|---|
| 1 | TLC from your `PATH` model-checked the `.tla` files. |
| 2 | TLC from `.tla-cache/tla2tools.jar` model-checked the `.tla` files. `MCP_GUARDRAIL_OFFLINE=1` stops the download. |
| 3 | Only the Rust mirror in `tests/tla_trace_equivalence.rs` ran. No tool read the `.tla` text. |

The script prints one line per spec:

- `PASS McpGuardrailTaint: ...` means the good spec holds all invariants (tiers 1 and 2), or the mirror test `spec_model_satisfies_all_invariants` passed (tier 3).
- `PASS McpGuardrailTaintBroken: violates NoUnapprovedTaintedSinkForwarded as expected` means the broken spec failed the way it must. That proves the check can fail.
- A `FAIL ...` line means a spec did not give its expected verdict. The script then prints `verify-tla: FAILED` and exits 1. It also exits 1 when no tier is available.
- `verify-tla: OK (tier <n>)` is the last line of a pass.

### The 3619 state count

On a tier 1 or tier 2 run, TLC must report `3619` distinct states for `McpGuardrailTaint` at `MaxCalls = 3`.

The Rust mirror prints the same count. Show it with this command:

```sh
cargo test --test tla_trace_equivalence -- --exact spec_model_satisfies_all_invariants --nocapture
```

A different count means the spec and the mirror diverged. Find out which one changed before you go on.

### Why you need the full suite

`cargo test --test tla_trace_equivalence` is not enough. It skips these checks:

- `engine_allow_implies_abstract_allow`, the agreement test. It guards drift between `classify` and `evaluate`, because the proxy decides with `PolicyEngine::evaluate` and the model checks `SessionTaintState::decide`.
- The rule unit tests in `src/policy.rs`. They guard the policy content, together with the replay corpus.
- The proxy ordering tests. They tie the proxy to the model's phase order.

## Read a counterexample

The Rust checker prints a violation of the model like this:

```text
<Invariant> violated after <n> actions:
  0: Init -> <state>
  1: <action> -> <state>
  2: <action> -> <state>
```

Each numbered line holds an action and the state it leads to. The depth-5 search of the implementation prints inputs, not actions:

```text
<check> failed after <n> inputs: <detail>
  1: <input>
  2: <input>
```

TLC prints this when an invariant fails:

```text
Error: Invariant <name> is violated.
State 1: <Initial predicate>
...
State 2: <Action line ...>
...
```

Each `State <n>` block lists the value of every variable after one action. To find the code behind an action, use the "Spec-to-code map" below.

If `/statechart` exists in your environment, feed it the trace to draw the phase diagram. If it does not, draw the five phases by hand: Idle, Received, Evaluated, Audited, Done.

## Prove a deliberate break before you move the sync commit

Do these steps in order. Do not skip step 1, because step 4 discards uncommitted edits to `src/taint.rs`.

1. Commit your change.
2. Make `SessionTaintState::decide` in `src/taint.rs` ignore taint for `PrivilegedSink`: set the `unapproved_tainted_sink` condition to `false`, so a tainted sink without an override is allowed. Deleting the `self.is_tainted()` conjunct instead breaks `engine_allow_implies_abstract_allow` first, and `cargo test` stops before the trace test runs.
3. Run `cargo test`. See `implementation_matches_spec_model_to_depth_5` fail on `NoUnapprovedTaintedSinkForwarded` with a 2-input trace. The trace is `UntrustedSource`, then `PrivilegedSink` without override. The iterative-deepening search reports the shortest trace first.
4. Run `git restore src/taint.rs`. Step 1 committed your change, so this command removes only the break.
5. Run `cargo test` and see it pass.
6. Only after every command under "Run both verification paths" passes on the commit from step 1, set `metadata.sync-commit` to that commit's hash in a follow-up commit.

## Spec-to-code map

| TLA+ | `src/taint.rs` | `src/proxy.rs` |
|---|---|---|
| `sessionTaint` | `TaintLevel`, `SessionTaintState::level()` | `taint.is_tainted()` at evaluation |
| `taintHistory` | `history() -> &[TaintEvent]`, at most `MAX_TAINT_HISTORY` events | `taint_chain()` in the audit line and the error data |
| `pendingCall` | `AbstractCall { tool_name, category, sensitivity, override_allowed }` | `McpCall` plus `Evaluation.category` and `Evaluation.sensitivity` |
| `Evaluate`, `Decide` | `decide(&AbstractCall) -> Decision` | `PolicyEngine::evaluate` plus the approval broker |
| `Audit`, `auditLog` | `AuditEntry` in `StepOutcome`, built before any taint update | `emit_event` writes one JSONL line |
| `Forward` | `forwarded = true`, then `record_forwarded` | `Verdict::Forward`, then `record_forwarded` |
| `Reject` | `forwarded = false` | `Verdict::Reply` with `-32001` or `-32002` |
| `Reset` | `reset()`, a no-op when `Clean` | not reachable from the proxy |
| `override` | `AbstractCall.override_allowed` | the broker returns `Approved` for a `require-approval` rule |
