//! `NamedRule` — late-bound parser reference.
//!
//! Mirrors `abnf.parser.Rule` (the parts that are also a parser):
//! a name plus a lazily-set `definition`.

use std::cell::Cell;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use smallvec::{smallvec, SmallVec};

use crate::error::ParseError;
use crate::matcher::Match;
use crate::node::{Node, NodeKind};
use crate::parser::{ArcParser, MatchList, ParseResult};

/// Maximum nested rule-recursion depth.  A left-recursive grammar
/// (`a = a "x" / "x"`) would otherwise recurse through Rust native
/// frames until the OS stack is exhausted and SIGSEGV the whole
/// process.  Python's `Rule.lparse` raises `RecursionError` from
/// CPython's interpreter-level guard at roughly the same depth;
/// matching that bound keeps behaviour comparable across backends.
const MAX_RULE_RECURSION: usize = 1000;

thread_local! {
    static RULE_RECURSION_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// RAII guard that increments the recursion counter on construction
/// and decrements on drop, so depth is restored even if the inner
/// `lparse` returns `Err` or panics.
struct DepthGuard;

impl DepthGuard {
    /// Try to enter a new recursion level.  Returns `None` when the
    /// depth limit is already reached, in which case the caller must
    /// short-circuit with a `ParseError` rather than recursing.
    fn enter() -> Option<Self> {
        RULE_RECURSION_DEPTH.with(|d| {
            let cur = d.get();
            if cur >= MAX_RULE_RECURSION {
                None
            } else {
                d.set(cur + 1);
                Some(Self)
            }
        })
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        RULE_RECURSION_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

#[derive(Debug)]
pub struct NamedRule {
    pub name: Arc<str>,
    definition: RwLock<Option<ArcParser>>,
    /// Pre-formatted error description (`"Rule(<name>)"`), computed
    /// once at construction and cloned cheaply (Arc bump) on every
    /// failed parse.  Without this, alternation backtracking through
    /// a rule reference paid a `format!` allocation per discarded
    /// `ParseError`.
    error_label: Arc<str>,
}

impl NamedRule {
    pub fn new(name: impl Into<Arc<str>>) -> Self {
        let name: Arc<str> = name.into();
        let error_label: Arc<str> = format!("Rule({name})").into();
        Self {
            name,
            definition: RwLock::new(None),
            error_label,
        }
    }

    pub fn set_definition(&self, def: ArcParser) {
        // Tolerate a poisoned lock: even if a panic in an earlier
        // code path left it poisoned, we still want to record the
        // new definition rather than permanently brick every parse
        // that touches this rule.
        *self
            .definition
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(def);
    }

    pub fn definition(&self) -> Option<ArcParser> {
        self.definition
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn parse_error(&self, start: usize) -> ParseError {
        ParseError::new(self.error_label.clone(), start)
    }

    pub fn lparse(&self, source: &str, start: usize) -> ParseResult {
        // Bound recursion depth so left-recursive grammars surface as
        // a catchable Python exception instead of overflowing the
        // native stack and SIGSEGVing the process.  `_guard` releases
        // the depth slot on every exit path (Ok, Err, panic).
        //
        // We `panic!` rather than returning `Err(ParseError)` because
        // `Alternation` / `Repetition` swallow `ParseError` to drive
        // backtracking: if we returned a recoverable error, the
        // bottoming-out depth-limit branch would silently succeed by
        // backtracking through every recursive call, hiding the
        // grammar bug.  Python's CPython interpreter handles this
        // case by raising `RecursionError`, which propagates straight
        // through `except ParseError`.  PyO3 maps Rust panics into a
        // catchable `PanicException` on the Python side, so the
        // resulting behaviour matches the pure-Python backend
        // contract (exception, not a silent success or a segfault).
        let _guard = DepthGuard::enter().unwrap_or_else(|| {
            panic!(
                "maximum rule recursion depth exceeded \
                 (likely a left-recursive grammar) in rule '{}'",
                self.name
            )
        });
        let def = self.definition().ok_or_else(|| self.parse_error(start))?;
        let inner = def.lparse(source, start)?;

        // Hot path: most rules produce exactly one match.  Skip the
        // dedup allocation entirely.
        if inner.len() == 1 {
            let m = inner.into_iter().next().expect("len == 1");
            let node = Node::new(self.name.clone(), m.nodes.into_vec());
            return Ok(smallvec![Match::new(
                smallvec![NodeKind::Internal(node)],
                m.start,
            )]);
        }

        // Multi-match (ambiguous grammar): dedup by end position.
        let mut seen: HashSet<usize> = HashSet::new();
        let mut wrapped: MatchList = SmallVec::with_capacity(inner.len());
        for m in inner {
            if !seen.insert(m.start) {
                continue;
            }
            let node = Node::new(self.name.clone(), m.nodes.into_vec());
            wrapped.push(Match::new(
                smallvec![NodeKind::Internal(node)],
                m.start,
            ));
        }
        if wrapped.is_empty() {
            Err(self.parse_error(start))
        } else {
            Ok(wrapped)
        }
    }
}
