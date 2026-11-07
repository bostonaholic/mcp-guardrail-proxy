#!/usr/bin/env bash
# Model-checks specs/McpGuardrailTaint.tla and the machine specs in MACHINE_SPECS.
# Each spec has a broken variant that must fail, which proves the check can fail.
# Each machine spec's state graph must match specs/graphs/<spec>.graph, the file
# the Rust machines are walked against; --update-graphs rewrites those files.
#
# Runs the first available tier only; once a tier starts, its verdict is final.
#   1. tlc on PATH
#   2. java + .tla-cache/tla2tools.jar (downloaded unless MCP_GUARDRAIL_OFFLINE=1)
#   3. the std-only Rust mirror in tests/tla_trace_equivalence.rs (cargo, else rustc),
#      and the walks of the committed graphs (cargo only). No tool reads the .tla text.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CACHE="$ROOT/.tla-cache"
JAR="$CACHE/tla2tools.jar"
JAR_URL="https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar"
GOOD_SPEC="McpGuardrailTaint"
BROKEN_SPEC="McpGuardrailTaintBroken"
GOOD_EVIDENCE="Model checking completed. No error has been found."
BROKEN_EVIDENCE="Invariant NoUnapprovedTaintedSinkForwarded is violated"
BROKEN_PASS="PASS $BROKEN_SPEC: violates NoUnapprovedTaintedSinkForwarded as expected"
GOOD_TEST="spec_model_satisfies_all_invariants"
BROKEN_TEST="broken_spec_model_violates_no_unapproved_tainted_sink_forwarded"
MACHINE_SPECS="LineFramer LineSplitter LineWriter CallJudgment SessionLifecycle AuditLogTail DashboardWatch"
# Each line: <broken spec> <what TLC must report>.
MACHINE_BREAKS="LineFramerBroken Invariant CompleteIsWholeLine is violated
LineSplitterBroken Invariant BytesAreConserved is violated
LineWriterBroken Invariant TornIsTracked is violated
CallJudgmentBroken Invariant FallbackNeverForwards is violated
SessionLifecycleBroken Temporal properties were violated
AuditLogTailBroken Invariant CursorTracksCurrentFile is violated
DashboardWatchBroken Invariant ScreenIsCurrent is violated
DashboardWatchHistoryBroken Invariant HistoryStaysSilent is violated"
# The walks of the committed graphs that the root crate runs.
GRAPH_WALK_TESTS="machines::framer::tests::framer_matches_every_edge_of_the_spec
machines::splitter::tests::splitter_matches_every_edge_of_the_spec
telemetry::tests::line_writer_matches_every_edge_of_the_spec
machines::call::tests::call_phase_matches_every_edge_of_the_spec
machines::session::tests::lifecycle_matches_every_edge_of_the_spec"

update_graphs=0
if [ "${1:-}" = "--update-graphs" ]; then
  update_graphs=1
fi

failures=0

fail() {
  echo "FAIL $*"
  failures=$((failures + 1))
}

has() {
  command -v "$1" >/dev/null 2>&1
}

finish() {
  if [ "$failures" -eq 0 ]; then
    echo "verify-tla: OK (tier $1)"
    exit 0
  fi
  echo "verify-tla: FAILED"
  exit 1
}

sha256_of() {
  if has sha256sum; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# Tier 2 is available when java exists and the jar is cached or downloads.
tier2_available() {
  has java || return 1
  [ -f "$JAR" ] && return 0
  [ "${MCP_GUARDRAIL_OFFLINE:-0}" = "1" ] && return 1
  has curl || return 1
  mkdir -p "$CACHE"
  if curl -fsSL --max-time 60 -o "$JAR.part" "$JAR_URL"; then
    mv "$JAR.part" "$JAR"
    echo "verify-tla: downloaded tla2tools.jar, sha256 $(sha256_of "$JAR")"
    return 0
  fi
  rm -f "$JAR.part"
  return 1
}

# run_tlc <spec> <tlc command...>: runs TLC on a fresh copy of specs/ under
# .tla-cache/run/<spec>, so states/ and trace files never touch tracked paths.
run_tlc() {
  local spec=$1
  shift
  local dir="$CACHE/run/$spec"
  rm -rf "$dir"
  mkdir -p "$dir"
  cp specs/*.tla specs/*.cfg "$dir/"
  (cd "$dir" && "$@" -config "$spec.cfg" "$spec.tla" 2>&1)
}

# check_machine_spec <spec> <tlc command...>: model-checks one machine spec and
# compares its state graph with the committed one.
check_machine_spec() {
  local spec=$1 out status graph committed
  shift
  committed="specs/graphs/$spec.graph"
  graph="$CACHE/run/$spec/$spec.graph"

  status=0
  out=$(run_tlc "$spec" "$@" -dump dot,actionlabels state-graph) || status=$?
  if [ "$status" -ne 0 ] || ! grep -qF "$GOOD_EVIDENCE" <<<"$out"; then
    printf '%s\n' "$out"
    fail "$spec: TLC exited $status; expected 0 and \"$GOOD_EVIDENCE\""
    return
  fi
  awk -f scripts/spec-graph.awk "$CACHE/run/$spec/state-graph.dot" | LC_ALL=C sort >"$graph"
  if [ "$update_graphs" -eq 1 ]; then
    mkdir -p specs/graphs
    cp "$graph" "$committed"
  fi
  if ! diff -q "$graph" "$committed" >/dev/null 2>&1; then
    fail "$spec: $committed does not match the spec; run scripts/verify-tla.sh --update-graphs"
    return
  fi
  echo "PASS $spec: TLC found no error, $(grep -c '^edge' "$graph") edges match $committed"
}

# check_machine_break <tlc command...> reads the MACHINE_BREAKS lines.
check_machine_breaks() {
  local spec evidence out status
  while read -r spec evidence; do
    status=0
    out=$(run_tlc "$spec" "$@") || status=$?
    if [ "$status" -ne 0 ] && grep -qF "$evidence" <<<"$out"; then
      echo "PASS $spec: $evidence, as expected"
    else
      printf '%s\n' "$out"
      fail "$spec: TLC exited $status; expected non-zero and \"$evidence\""
    fi
  done <<<"$MACHINE_BREAKS"
}

# check_with_tlc <tlc command...>: tiers 1 and 2.
check_with_tlc() {
  local out status spec

  status=0
  out=$(run_tlc "$GOOD_SPEC" "$@") || status=$?
  if [ "$status" -eq 0 ] && grep -qF "$GOOD_EVIDENCE" <<<"$out"; then
    echo "PASS $GOOD_SPEC: TLC found no error (MaxCalls = 3)"
  else
    printf '%s\n' "$out"
    fail "$GOOD_SPEC: TLC exited $status; expected 0 and \"$GOOD_EVIDENCE\""
  fi

  status=0
  out=$(run_tlc "$BROKEN_SPEC" "$@") || status=$?
  if [ "$status" -ne 0 ] && grep -qF "$BROKEN_EVIDENCE" <<<"$out"; then
    echo "$BROKEN_PASS"
  else
    printf '%s\n' "$out"
    fail "$BROKEN_SPEC: TLC exited $status; expected non-zero and \"$BROKEN_EVIDENCE\""
  fi

  for spec in $MACHINE_SPECS; do
    check_machine_spec "$spec" "$@"
  done
  check_machine_breaks "$@"
}

# run_mirror_test <runner> <test name>: runs one test of the Rust mirror.
# --exact makes a renamed test show up as "0 passed" instead of a silent pass.
run_mirror_test() {
  if [ "$1" = cargo ]; then
    cargo test --test tla_trace_equivalence -- --nocapture --exact "$2" 2>&1
  else
    "$CACHE/tla_trace_equivalence" --nocapture --exact "$2" 2>&1
  fi
}

# check_with_mirror <runner>: tier 3. The two test verdicts are the evidence.
check_with_mirror() {
  local runner=$1 out status

  if [ "$runner" = rustc ]; then
    mkdir -p "$CACHE"
    status=0
    out=$(rustc --edition 2024 --test tests/tla_trace_equivalence.rs \
      -o "$CACHE/tla_trace_equivalence" 2>&1) || status=$?
    if [ "$status" -ne 0 ]; then
      printf '%s\n' "$out"
      fail "rustc could not build tests/tla_trace_equivalence.rs (exit $status)"
      return
    fi
  fi

  status=0
  out=$(run_mirror_test "$runner" "$GOOD_TEST") || status=$?
  printf '%s\n' "$out"
  if [ "$status" -eq 0 ] && grep -qF "test result: ok. 1 passed" <<<"$out"; then
    echo "PASS $GOOD_SPEC: $GOOD_TEST (Rust mirror, MaxCalls = 3)"
  else
    fail "$GOOD_SPEC: $GOOD_TEST did not pass (exit $status)"
  fi

  status=0
  out=$(run_mirror_test "$runner" "$BROKEN_TEST") || status=$?
  printf '%s\n' "$out"
  if [ "$status" -eq 0 ] && grep -qF "test result: ok. 1 passed" <<<"$out"; then
    echo "$BROKEN_PASS"
  else
    fail "$BROKEN_SPEC: $BROKEN_TEST did not pass (exit $status)"
  fi

  if [ "$runner" = rustc ]; then
    echo "SKIP machine specs: the graph walks need cargo"
    return
  fi
  local walk
  for walk in $GRAPH_WALK_TESTS; do
    status=0
    out=$(cargo test --lib -- --exact "$walk" 2>&1) || status=$?
    if [ "$status" -eq 0 ] && grep -qF "test result: ok. 1 passed" <<<"$out"; then
      echo "PASS $walk (committed graph; TLC did not run)"
    else
      printf '%s\n' "$out"
      fail "$walk did not pass (exit $status)"
    fi
  done
}

if has tlc; then
  echo "verify-tla: tier 1 (tlc on PATH)"
  check_with_tlc tlc
  finish 1
fi

if tier2_available; then
  echo "verify-tla: tier 2 (java + .tla-cache/tla2tools.jar)"
  check_with_tlc java -cp "$JAR" tlc2.TLC
  finish 2
fi

if [ -f Cargo.toml ] && has cargo; then
  echo "verify-tla: tier 3 (Rust mirror via cargo test)"
  check_with_mirror cargo
  finish 3
fi

if [ -f tests/tla_trace_equivalence.rs ] && has rustc; then
  echo "verify-tla: tier 3 (Rust mirror via rustc --test)"
  check_with_mirror rustc
  finish 3
fi

missing="tlc"
has java || missing="$missing java"
if has java && [ ! -f "$JAR" ]; then
  missing="$missing .tla-cache/tla2tools.jar"
fi
has cargo || missing="$missing cargo"
has rustc || missing="$missing rustc"
[ -f tests/tla_trace_equivalence.rs ] || missing="$missing tests/tla_trace_equivalence.rs"
fail "no verification tier available; missing: $missing"
echo "verify-tla: FAILED"
exit 1
