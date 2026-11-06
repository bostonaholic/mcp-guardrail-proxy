# Vision

mcp-guardrail-proxy exists so that an agent which reads untrusted content cannot be turned into a channel that leaks data or runs destructive commands. The proxy enforces that outside the model, at the only place every tool call must pass: the stdio pipe between the MCP host and the server.

## The problem

An agent reads a web page, an email, or an issue. The text holds an instruction. The model follows it and calls a tool that sends data out or runs a shell command. No prompt, system message, or model update makes this impossible, because the model is the thing being attacked.

The host and the server each see only their side. The host trusts the model. The server trusts the host. Nothing in the chain remembers that the session already read untrusted content when the next call arrives.

## The bet

Three ideas carry the project.

1. **Taint is the primitive.** A session that has read untrusted content is tainted, and the taint only goes away through a recorded reset. Policy decisions depend on that state, so the same `shell` call is allowed in a clean session and denied in a tainted one. This is the one fact the host and server both lack, and the proxy is the one place that can hold it.

2. **Enforcement belongs at the transport boundary.** The proxy judges each `tools/call` and `resources/read` frame before the server sees it. A denied call never reaches the child. The model's opinion of the call does not matter. The policy is a TOML file that a person can read, diff, and check with `check-policy`, not a prompt.

3. **The core is small enough to prove.** The taint state machine and the decision order are modeled in TLA+ and mirrored in Rust tests. Four invariants hold: a tainted session never forwards a privileged sink without approval, sensitive arguments never reach the child, taint is monotonic, and every forward follows its audit entry. A deliberate break in the spec must fail the check, and the repository records the commit on which the proof last passed.

## What it is

- One binary, no network calls, no daemon. It wraps one stdio server and relays everything else unchanged.
- A declarative policy engine. Taint sources and rules are regexes over the tool name and the argument text. `deny` beats `require-approval` beats `allow`.
- An audit trail. One redacted JSON line per decision, written before the call is forwarded, through a sink that fails closed.
- A replay corpus. Prompt-injection scenarios run against the policy on every change and report precision, recall, and latency.
- A library with three seams. `PolicyProvider`, `AuditSink`, and `ApprovalBroker` let a remote control plane supply policy, collect audit events, and answer approvals without a change to the engine. The local defaults read a file, write JSON lines, and leave every approval pending.

## What it is not

- Not a model-side defense. It does not read tool results, score prompts, or detect injection text. It assumes the model will be fooled and limits what a fooled model can do.
- Not a sandbox. It sees arguments, not effects. A tool whose name matches no rule is allowed, and a regex can be obfuscated around. The README lists the known misses.
- Not an HTTP proxy. Remote MCP servers that speak over `url` are out of scope until the transport layer is separate from the interceptor.
- Not a policy marketplace. The default policy is a starting point that a team copies and edits, and the engine refuses a file with a typo in it.

## Principles

- **Fail closed.** A broken audit sink, a bad policy file, or a frame the proxy cannot classify produces a denial or an error, never a silent forward.
- **The decision is explainable.** Every denial names the rule, the severity, the reason text from the policy, and the taint chain that led there. A person reading the audit line can reconstruct why.
- **Taint never lies.** A call taints the session only after it is forwarded, and the state updates before the next line is read. The spec and the code agree on this order.
- **Policy is data.** New sources and rules are TOML, not code. Adding a rule should never need a rebuild.
- **Prove the core, test the edges.** Formal invariants cover the state machine. Replay scenarios and integration tests cover the regexes, the redaction, and the JSON-RPC edge cases that a spec would not express well.
- **No surprises in the pipe.** The handshake, notifications, responses, and every method the policy does not evaluate pass through byte for byte. Child stderr is relayed, and audit lines never interleave with it.

## Direction

The order below is a judgment of value against effort. Nothing here is a commitment.

1. **Taint across servers.** One proxy per server means one taint state per server. The near-term answer is to wrap an aggregator and accept prefixed tool names in the default regexes. The long-term answer is shared taint state that several proxies for one host can read and write, without the proxy growing a network stack of its own.
2. **A real approval broker.** `require-approval` today leaves the call pending. A local broker that prompts the person, and a remote broker behind the existing trait, turn the medium-severity rules into a workflow instead of a soft deny.
3. **Better classifiers behind the same policy shape.** Percent-decoding and path normalization before matching. Argument-level sources, such as a `read_file` of a downloaded path. A `tool_regex` that matches on the tool's declared schema, not only its name. Each of these stays a policy field with a regex-like contract, so a policy file keeps meaning the same thing.
4. **Taint reset.** The spec already allows a recorded reset. The binary does not expose one. A reset that is explicit, audited, and host-initiated lets a long session recover without a restart.
5. **HTTP transport.** Separate the interceptor from the stdio relay so the same engine fronts a remote MCP server.

The open-core seam is the shape of all of this. The engine, the policy format, the audit format, and the proof stay open. A control plane that distributes policy, collects audit, and brokers approvals across a fleet can be built on the traits without forking the engine.

## How to judge a change

A change fits the vision when:

- A denial it adds is explainable from the audit line alone.
- It keeps the four invariants and moves the sync commit after the checks pass.
- It adds no network call to the data plane.
- A policy file written for the previous version still loads and means the same thing, or the change says why not.
- The replay corpus gains a scenario for any new attack it claims to stop.
