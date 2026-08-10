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
/// process.
///
/// This bound alone is not enough: it counts levels, while the
/// resource being protected is stack *bytes*.  See `STACK_BUDGET`.
const MAX_RULE_RECURSION: usize = 1000;

/// Smallest main-thread stack we assume.  Linux and macOS hand the
/// main thread ~8 MiB; Windows reserves substantially less (the
/// crash in issue #170 puts it under 3 MiB, and the MSVC default is
/// 1 MiB).  Worker threads can be smaller still on any platform —
/// `threading.stack_size()` reproduces the Windows failure on Linux
/// and macOS exactly.
const MIN_SUPPORTED_STACK: usize = 1024 * 1024;

/// Native stack a single `parse` may consume through nested rule
/// recursion.  Half of `MIN_SUPPORTED_STACK`, leaving headroom for
/// the Python frames above the outermost `lparse` and for the
/// deepest Rust frame below the check that trips it.
///
/// Issue #170: `MAX_RULE_RECURSION` was set to 1000 to mirror
/// CPython's default recursion limit, on the theory that matching
/// counts keeps the backends comparable.  It doesn't — a rule level
/// costs ~2-3 KiB of native stack here, so 1000 levels wants ~3 MiB.
/// Where the stack is bigger than that the counter fires first and
/// all is well; where it is smaller the stack is gone before the
/// counter is anywhere near 1000, and the process dies with no
/// catchable error at all.  Budgeting bytes makes the guard fire on
/// the resource that actually runs out, so behaviour is the same on
/// every platform and on every thread.
///
/// The cost is a lower ceiling than a large stack could support
/// (~170 levels rather than ~1000).  ABNF grammars nest in the
/// single digits in practice; anything approaching this bound is
/// pathological input, which is what the guard is for.
const STACK_BUDGET: usize = MIN_SUPPORTED_STACK / 2;

thread_local! {
    static RULE_RECURSION_DEPTH: Cell<usize> = const { Cell::new(0) };
    /// Address of a local in the frame that entered rule recursion,
    /// i.e. the outermost `NamedRule::lparse` on this thread.  Zero
    /// when no parse is in flight.  Distance from here to the
    /// current frame is how much stack the recursion has eaten.
    static STACK_ANCHOR: Cell<usize> = const { Cell::new(0) };
}

/// Address of a local in the calling frame, used to measure stack
/// consumption.  `black_box` forces `probe` into a real stack slot
/// rather than a register, and `inline(always)` keeps the slot in
/// the caller's frame instead of one belonging to this function.
///
/// Comparing addresses of locals in different frames is not
/// something the abstract machine promises anything about, but the
/// arithmetic is on plain `usize` values, so nothing here is UB —
/// it is an assumption about how stacks work on the targets we
/// build for, and `abs_diff` keeps it agnostic to growth direction.
#[inline(always)]
fn stack_probe() -> usize {
    let probe = 0u8;
    core::hint::black_box(&probe) as *const u8 as usize
}

/// Why `DepthGuard::enter` refused to recurse another level.
enum Limit {
    /// Level count hit `MAX_RULE_RECURSION` — the classic
    /// left-recursion signature, caught before the stack matters.
    Depth,
    /// Stack consumption hit `STACK_BUDGET` — deep nesting on a
    /// stack too small to reach the level count.
    Stack { consumed: usize, depth: usize },
}

/// RAII guard that increments the recursion counter on construction
/// and decrements on drop, so depth is restored even if the inner
/// `lparse` returns `Err` or panics.
struct DepthGuard;

impl DepthGuard {
    /// Try to enter a new recursion level.  Returns `Err` when
    /// either bound is reached, in which case the caller must
    /// short-circuit rather than recursing.
    ///
    /// The outermost level records the stack anchor; every level
    /// below it measures against that anchor.  A parse re-entered
    /// from Python mid-recursion (a `PyCallbackParser` callback that
    /// parses again) keeps the outer anchor, which is correct: its
    /// frames sit on the same stack and count against the same
    /// budget.
    fn enter() -> Result<Self, Limit> {
        let here = stack_probe();
        RULE_RECURSION_DEPTH.with(|d| {
            let cur = d.get();
            if cur >= MAX_RULE_RECURSION {
                return Err(Limit::Depth);
            }
            if cur == 0 {
                STACK_ANCHOR.with(|a| a.set(here));
            } else {
                let consumed = STACK_ANCHOR.with(|a| a.get()).abs_diff(here);
                if consumed > STACK_BUDGET {
                    return Err(Limit::Stack {
                        consumed,
                        depth: cur,
                    });
                }
            }
            d.set(cur + 1);
            Ok(Self)
        })
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        RULE_RECURSION_DEPTH.with(|d| {
            let next = d.get().saturating_sub(1);
            d.set(next);
            if next == 0 {
                // Unwinding from the depth/stack panic drops every
                // guard on the way out, so this also re-arms the
                // anchor for the next parse on this thread.
                STACK_ANCHOR.with(|a| a.set(0));
            }
        });
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
        //
        // Both bounds panic with the same leading phrase because the
        // PyO3 layer keys on it (`DEPTH_PANIC_TAG`) to convert the
        // panic into `RecursionError`.  Only the detail differs, so
        // a traceback says which limit was hit.
        let _guard = DepthGuard::enter().unwrap_or_else(|limit| match limit {
            Limit::Depth => panic!(
                "maximum rule recursion depth exceeded \
                 (likely a left-recursive grammar) in rule '{}'",
                self.name
            ),
            Limit::Stack { consumed, depth } => panic!(
                "maximum rule recursion depth exceeded: native stack budget \
                 of {STACK_BUDGET} bytes exhausted ({consumed} consumed at \
                 depth {depth}) in rule '{}' -- input is nested too deeply \
                 for this thread's stack",
                self.name
            ),
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
