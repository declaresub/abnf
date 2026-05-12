//! `NamedRule` — late-bound parser reference.
//!
//! Mirrors `abnf.parser.Rule` (the parts that are also a parser):
//! a name plus a lazily-set `definition`.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use smallvec::{smallvec, SmallVec};

use crate::error::ParseError;
use crate::matcher::Match;
use crate::node::{Node, NodeKind};
use crate::parser::{ArcParser, MatchList, ParseResult};

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
        *self.definition.write().expect("NamedRule lock poisoned") = Some(def);
    }

    pub fn definition(&self) -> Option<ArcParser> {
        self.definition
            .read()
            .expect("NamedRule lock poisoned")
            .clone()
    }

    fn parse_error(&self, start: usize) -> ParseError {
        ParseError::new(self.error_label.clone(), start)
    }

    pub fn lparse(&self, source: &str, start: usize) -> ParseResult {
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
