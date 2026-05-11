//! `NamedRule` — late-bound parser reference.
//!
//! Mirrors `abnf.parser.Rule` (the parts that are also a parser):
//! a name plus a lazily-set `definition`.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use crate::error::ParseError;
use crate::matcher::Match;
use crate::node::{Node, NodeKind};
use crate::parser::{ArcParser, ParseResult};

#[derive(Debug)]
pub struct NamedRule {
    pub name: Arc<str>,
    definition: RwLock<Option<ArcParser>>,
}

impl NamedRule {
    pub fn new(name: impl Into<Arc<str>>) -> Self {
        Self {
            name: name.into(),
            definition: RwLock::new(None),
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

    pub fn lparse(&self, source: &str, start: usize) -> ParseResult {
        let def = self.definition().ok_or_else(|| {
            ParseError::new(format!("Rule({})", self.name), start)
        })?;
        let inner = def.lparse(source, start)?;

        let mut seen: HashSet<MatchKey> = HashSet::new();
        let mut wrapped: Vec<Match> = Vec::new();
        for m in inner {
            let key = MatchKey {
                value: m.value(),
                start: m.start,
            };
            if seen.insert(key) {
                let node = Node::new(self.name.clone(), m.nodes);
                wrapped.push(Match::new(vec![NodeKind::Internal(node)], m.start));
            }
        }
        if wrapped.is_empty() {
            Err(ParseError::new(format!("Rule({})", self.name), start))
        } else {
            Ok(wrapped)
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
struct MatchKey {
    value: String,
    start: usize,
}
