//! `NamedRule` — late-bound parser reference.
//!
//! Mirrors `abnf.parser.Rule` (the parts that are also a parser):
//! a name plus a lazily-set `definition`, which lets the meta-grammar
//! and user-supplied rule lists contain forward references.  Multiple
//! references to the same rule share the same underlying definition
//! cell, so updating a rule (the `=/` operator) is observed by every
//! reference.
//!
//! The full Python `Rule` (with its registry, `exclude_rule`,
//! `first_match_alternation` property, `create`/`load_grammar`/...)
//! lives in the Python facade and is not duplicated here.  This type
//! is only the parser-side of a rule.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use crate::error::ParseError;
use crate::matcher::Match;
use crate::node::{Node, NodeKind};
use crate::parser::{ArcParser, ParseResult, ParserOp};

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

    /// Set (or replace) the definition that this rule parses against.
    pub fn set_definition(&self, def: ArcParser) {
        *self.definition.write().expect("NamedRule lock poisoned") = Some(def);
    }

    /// Returns the current definition, if any.
    pub fn definition(&self) -> Option<ArcParser> {
        self.definition.read().expect("NamedRule lock poisoned").clone()
    }
}

impl ParserOp for NamedRule {
    fn lparse(&self, source: &str, start: usize) -> ParseResult {
        let def = self.definition().ok_or_else(|| {
            ParseError::new(format!("Rule({})", self.name), start)
        })?;
        let inner = def.lparse(source, start)?;

        // Mirror Python: de-duplicate by (concatenated-value, start)
        // then wrap each match's nodes in a Node carrying this rule's
        // name.  If de-duplication leaves nothing, raise ParseError —
        // the rule has no valid match at this position.
        let mut seen: HashSet<MatchKey> = HashSet::new();
        let mut wrapped: Vec<Match> = Vec::new();
        for m in inner {
            let key = MatchKey { value: m.value(), start: m.start };
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
