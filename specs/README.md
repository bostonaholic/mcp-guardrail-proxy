# State machines

Every piece of code that remembers something between events and changes what it does because of it is listed here, with how it is checked. A search of `src`, `desktop/src`, and `desktop/ui` for such state produced this list.

## The machines

| Machine | Code | Spec | What the spec proves |
|---|---|---|---|
| Session taint | `SessionTaintState`, `src/taint.rs` | `McpGuardrailTaint` | The four invariants in the root README. |
| One call's judgment | `CallPhase`, `src/machines/call.rs` | `CallJudgment` | The broker's answers and a failed audit sink. The child sees a call only after a durable audit line, a failed audit never forwards or taints, and a tainted sink needs approval. |
| Session lifecycle | `SessionLifecycle`, `src/machines/session.rs` | `SessionLifecycle` | Any order of host EOF, child exit, relay end, and host failure reaps the child, writes or gives up on every queued line, returns the right outcome, and terminates. |
| Line reader | `LineFramer`, `src/machines/framer.rs` | `LineFramer` | Memory stays within the cap, a frame is always a whole line, and the tail of an oversize line never comes out as a frame. |
| Stderr splitter | `LineSplitter`, `src/machines/splitter.rs` | `LineSplitter` | No byte is lost or invented, and lines stay within the cap. |
| Line boundary | `LineBoundary`, `src/telemetry.rs` | `LineWriter` | A torn write never joins the next line, so an audit line stays whole on a shared stream. |
| Log cursor | `TailCursor`, `desktop/src/tail.rs` | `AuditLogTail` | After a poll the cursor counts bytes of the current file, so no line is skipped. Read the assumption at the top of the spec. |
| Poll gate | `Watch`, `desktop/src/watch.rs` | `DashboardWatch` | After a poll the screen is current, and history never raises a notification. |

`CallJudgment` refines the per-call phases of `McpGuardrailTaint` at the grain of the code. `McpGuardrailTaint` stays the abstract proof of the taint rule, so its state count and Rust mirror do not change.

## How a spec reaches the code

For every spec except `McpGuardrailTaint`, which has the hand-written mirror in `tests/tla_trace_equivalence.rs`:

1. TLC checks the invariants and writes the whole state graph.
2. `scripts/verify-tla.sh` normalizes that graph with `scripts/spec-graph.awk` and fails if it differs from `specs/graphs/<spec>.graph`.
3. A `*_matches_every_edge_of_the_spec` test walks the Rust machine along every edge of the committed graph, and fails at the first variable that differs.

So a change to the `.tla` file fails step 2 until the graph is regenerated, and a change to the Rust machine fails step 3. Tier 3 of the script has no TLC, so it runs step 3 only.

Each spec has a `*Broken.tla` variant that must fail, which proves the check can fail. The broken variants of `SessionLifecycle`, `AuditLogTail`, and `DashboardWatch` are the behavior of the code before its machine was explicit:

| Variant | The bug it records |
|---|---|
| `SessionLifecycleBroken` | With host input stuck writing to a child that stopped reading, a dead host went unnoticed and the session hung. |
| `AuditLogTailBroken` | A poll that found no file kept the old offset, so a new log lost its first lines. |
| `DashboardWatchBroken` | A launch read's error banner stayed after the file recovered, and a malformed line reached the screen only with the next audit event. |
| `DashboardWatchHistoryBroken` | After a failed launch read, the first read that worked sent a notification for history. |

## What this does not cover

- The walks check the pure machines. The driver that feeds them, `run_session` in `src/proxy.rs`, is covered by `tests/integration_test.rs`.
- The specs feed one byte at a time to `LineFramer` and `LineSplitter`, and the proxy feeds buffers. `chunk_size_never_changes_the_lines` covers the difference.
- The bounds are small: `Cap = 2` for the line machines, `MaxLen = 3` and `MaxGen = 3` for the cursor. No bound applies to `SessionLifecycle`, `CallJudgment`, or `LineWriter`, whose state spaces are finite as written.
- `SessionLifecycle` assumes a live host reads its output. A host that holds stdout open and stops reading stalls the writer, as it always has.
- A broken variant shows that one invariant per spec can fail, not all of them.

## Looked at and left out

| Candidate | Why it is not a machine here |
|---|---|
| `Interceptor::handle_host_line` | A pure classifier of one frame. It keeps nothing. |
| `PolicyEngine::evaluate` | A pure fold over the rules. `engine_allow_implies_abstract_allow` ties it to the taint rule. |
| Taint history eviction, `dropped_events` | Bookkeeping for the audit text, on top of an explicit machine. Unit tests in `src/taint.rs` cover it. |
| `Interceptor::sequence` | A counter that only grows. |
| `ApprovalOutcome` | One answer per call, held nowhere. `CallPhase` covers it. |
| `run_replay` | A loop over the corpus. Its only state is an `Interceptor`. |
| `latest` in `desktop/ui/app.js` | Empty until the first snapshot, then the last snapshot. |
| `Monitor` in `desktop/src/monitor.rs` | Its own state is the watched path and the notifications switch. A message compares one path with it once, like `latest`, and replaces the switch. The switch gates whole polls and keeps no record of dropped alerts. `TailCursor` and `Watch` keep the event-order rules under their own specs. |
| `SettingsStore` in `desktop/src/settings.rs` | It holds the last saved values. Each save replaces them, and no rule reads the order of earlier saves. |
| Window shown or hidden, notification permission | Held by Tauri and the OS, not by this code. |

## Adding or changing a machine

1. Write the spec and its `Broken` variant, with a `.cfg` for each, and add them to `MACHINE_SPECS` and `MACHINE_BREAKS` in `scripts/verify-tla.sh`.
2. Write each action as a conjunction with a guard. TLC names an edge after the definition it sees last, so `Foo == Bar(1)` shows up as `Bar`.
3. Run `scripts/verify-tla.sh --update-graphs`, and read the graph diff before you commit it.
4. Add a walk test, and add it to `GRAPH_WALK_TESTS` when it lives in the root crate.
