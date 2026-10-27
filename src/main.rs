//! Command line for the guardrail proxy: run it, replay a corpus, or check a policy.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use mcp_guardrail_proxy::control_plane::{AuditSink, PendingApprovalBroker};
use mcp_guardrail_proxy::policy::{PolicyEngine, PolicyError};
use mcp_guardrail_proxy::proxy::{ProxyConfig, ProxyError, run_stdio_proxy};
use mcp_guardrail_proxy::replay::{ReplayCorpus, run_replay};
use mcp_guardrail_proxy::telemetry::{JsonlAuditSink, SharedLineWriter};

/// Taint-aware guardrails for MCP tool calls.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sit between an MCP host (stdin, stdout) and an upstream server, enforcing the policy.
    Proxy {
        /// The policy file; without it, the embedded default policy applies.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Append audit lines here instead of writing them to stderr.
        #[arg(long)]
        audit_log: Option<PathBuf>,
        /// The id stamped on audit events; defaults to `<pid>-<unix_millis>`.
        #[arg(long, default_value_t = default_session_id())]
        session_id: String,
        /// The upstream server's program and arguments, after `--`.
        #[arg(last = true, required = true)]
        upstream: Vec<String>,
    },
    /// Replay a corpus of host frames against a policy and report the outcome.
    Replay {
        /// The policy file; without it, the embedded default policy applies.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// The corpus file.
        #[arg(long)]
        corpus: PathBuf,
    },
    /// Check that a policy loads.
    CheckPolicy {
        /// The policy file; without it, the embedded default policy applies.
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}

/// `<pid>-<unix_millis>`.
fn default_session_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    format!("{}-{millis}", std::process::id())
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Proxy {
            policy,
            audit_log,
            session_id,
            upstream,
        } => run_proxy(
            policy.as_deref(),
            audit_log.as_deref(),
            session_id,
            upstream,
        ),
        Command::Replay { policy, corpus } => run_replay_command(policy.as_deref(), &corpus),
        Command::CheckPolicy { policy } => run_check_policy(policy.as_deref()),
    }
}

/// The engine for the file at `policy`, or the embedded default when there is no path.
fn load_engine(policy: Option<&Path>) -> Result<PolicyEngine, PolicyError> {
    match policy {
        Some(path) => PolicyEngine::from_path(path),
        None => PolicyEngine::embedded_default(),
    }
}

fn run_proxy(
    policy: Option<&Path>,
    audit_log: Option<&std::path::Path>,
    session_id: String,
    upstream_command: Vec<String>,
) -> ExitCode {
    let engine = match load_engine(policy) {
        Ok(engine) => engine,
        Err(error) => {
            eprintln!("mcp-guardrail-proxy: policy error: {error}");
            return ExitCode::from(1);
        }
    };
    let stderr = SharedLineWriter::stderr();
    let audit_sink: Box<dyn AuditSink> = match audit_log {
        Some(path) => match JsonlAuditSink::create(path) {
            Ok(sink) => Box::new(sink),
            Err(error) => {
                eprintln!(
                    "mcp-guardrail-proxy: cannot open audit log {}: {error}",
                    path.display()
                );
                return ExitCode::from(1);
            }
        },
        None => Box::new(JsonlAuditSink::from_shared(stderr.clone())),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("mcp-guardrail-proxy: cannot start the async runtime: {error}");
            return ExitCode::from(1);
        }
    };
    let outcome = runtime.block_on(run_stdio_proxy(ProxyConfig {
        session_id,
        upstream_command,
        engine,
        audit_sink,
        approval_broker: Box::new(PendingApprovalBroker),
        stderr,
    }));
    // The stdin reader thread may stay blocked while the host holds stdin open; dropping the
    // runtime would wait for it, so detach instead.
    runtime.shutdown_background();
    match outcome {
        Ok(status) => exit_code(status.code()),
        Err(ProxyError::ChildExited(code)) => exit_code(code),
        Err(error) => {
            eprintln!("mcp-guardrail-proxy: {error}");
            ExitCode::from(1)
        }
    }
}

/// A child's exit code as ours; a child killed by a signal has none, which maps to 1.
fn exit_code(code: Option<i32>) -> ExitCode {
    let code = code.map_or(1, |code| u8::try_from(code.clamp(0, 255)).unwrap_or(1));
    ExitCode::from(code)
}

fn run_replay_command(policy: Option<&Path>, corpus: &std::path::Path) -> ExitCode {
    let engine = match load_engine(policy) {
        Ok(engine) => engine,
        Err(error) => {
            eprintln!("mcp-guardrail-proxy: policy error: {error}");
            return ExitCode::from(1);
        }
    };
    let corpus = match ReplayCorpus::from_path(corpus) {
        Ok(corpus) => corpus,
        Err(error) => {
            eprintln!("mcp-guardrail-proxy: {error}");
            return ExitCode::from(1);
        }
    };
    let report = run_replay(&engine, &corpus);
    println!("{}", report.render());
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn run_check_policy(policy: Option<&Path>) -> ExitCode {
    match load_engine(policy) {
        Ok(engine) => {
            let source = match policy {
                Some(path) => path.display().to_string(),
                None => "embedded default".to_string(),
            };
            println!(
                "policy OK: {source}: {} rules, {} taint sources",
                engine.rule_count(),
                engine.taint_source_count()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("policy error: {error}");
            ExitCode::from(1)
        }
    }
}
