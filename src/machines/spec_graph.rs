//! Reads a state graph from `specs/graphs` and walks a Rust machine along every edge.
//!
//! `scripts/verify-tla.sh` writes the graphs from TLC's output and fails when a committed
//! graph no longer matches its spec, so a walk ties the Rust code to the `.tla` text.

use std::collections::{BTreeMap, VecDeque};

/// One TLC state: each variable's name and value.
pub type Vars = BTreeMap<String, String>;

/// One edge of the state graph.
pub struct Step<'graph> {
    /// The name of the TLA+ action.
    pub action: &'graph str,
    /// The state after the action.
    pub to: &'graph Vars,
}

/// A Rust `bool` as TLC prints it.
pub fn tla_bool(value: bool) -> String {
    if value { "TRUE" } else { "FALSE" }.to_string()
}

/// A parsed `.graph` file.
pub struct SpecGraph {
    init: Vec<Vars>,
    edges: Vec<(Vars, String, Vars)>,
}

fn parse_vars(text: &str) -> Vars {
    text.split_whitespace()
        .map(|pair| {
            let (name, value) = pair
                .split_once('=')
                .expect("a state holds name=value pairs");
            (name.to_string(), value.to_string())
        })
        .collect()
}

impl SpecGraph {
    /// Parses `init <state>` and `edge <state> | <action> | <state>` lines.
    pub fn parse(text: &str) -> Self {
        let mut graph = SpecGraph {
            init: Vec::new(),
            edges: Vec::new(),
        };
        for line in text.lines() {
            if let Some(state) = line.strip_prefix("init ") {
                graph.init.push(parse_vars(state));
            } else if let Some(edge) = line.strip_prefix("edge ") {
                let parts: Vec<&str> = edge.split(" | ").collect();
                let [from, action, to] = parts[..] else {
                    panic!("malformed edge: {line}");
                };
                graph
                    .edges
                    .push((parse_vars(from), action.to_string(), parse_vars(to)));
            } else {
                panic!("malformed graph line: {line}");
            }
        }
        assert!(!graph.init.is_empty(), "the graph has no initial state");
        assert!(!graph.edges.is_empty(), "the graph has no edges");
        graph
    }

    /// Applies `step` along every edge, starting from `initial`, and panics at the first
    /// state where `project` disagrees with the graph. Returns the edge count.
    ///
    /// `project` names only the variables the machine holds, so ghost and environment
    /// variables stay out of the comparison. Every graph state must be reached.
    pub fn walk<M: Clone>(
        &self,
        initial: M,
        project: impl Fn(&M) -> Vec<(&'static str, String)>,
        step: impl Fn(&mut M, &Step<'_>),
    ) -> usize {
        let assert_matches = |machine: &M, state: &Vars, context: &str| {
            for (name, value) in project(machine) {
                let expected = state.get(name).unwrap_or_else(|| {
                    panic!("{context}: the spec has no variable {name}");
                });
                assert_eq!(
                    &value, expected,
                    "{context}: {name} differs from the spec state {state:?}"
                );
            }
        };
        let mut seen: BTreeMap<&Vars, M> = BTreeMap::new();
        let mut queue = VecDeque::new();
        for state in &self.init {
            assert_matches(&initial, state, "Init");
            seen.insert(state, initial.clone());
            queue.push_back(state);
        }
        let mut walked = 0;
        while let Some(state) = queue.pop_front() {
            let machine = seen[state].clone();
            for (from, action, to) in &self.edges {
                if from != state {
                    continue;
                }
                let mut next = machine.clone();
                step(&mut next, &Step { action, to });
                assert_matches(&next, to, action);
                walked += 1;
                if !seen.contains_key(to) {
                    seen.insert(to, next);
                    queue.push_back(to);
                }
            }
        }
        assert_eq!(walked, self.edges.len(), "some edges were not reached");
        walked
    }
}
