//! Guardrail proxy for MCP tool calls: JSON-RPC envelopes, policy, and taint tracking.

#![forbid(unsafe_code)]

pub mod control_plane;
pub mod policy;
pub mod protocol;
pub mod taint;
