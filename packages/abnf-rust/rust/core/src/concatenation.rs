//! `Concatenation` — sequence operator.
//!
//! Mirrors `abnf.parser.Concatenation` (`_parser_python.py:157-189`):
//! builds an enumeration of (combined-nodes, end-position) pairs by
//! iteratively extending each accumulated prefix through every
//! subsequent parser.  If at any stage every prefix dies, the whole
//! concatenation errors at the original `start`.

use crate::error::ParseError;
use crate::matcher::Match;
use crate::parser::{ArcParser, ParseResult, ParserOp};

#[derive(Debug)]
pub struct Concatenation {
    pub parsers: Vec<ArcParser>,
}

impl Concatenation {
    pub fn new(parsers: Vec<ArcParser>) -> Self {
        Self { parsers }
    }
}

impl ParserOp for Concatenation {
    fn lparse(&self, source: &str, start: usize) -> ParseResult {
        // The seed is a single empty match at `start`; each parser
        // extends every surviving prefix.
        let mut match_list: Vec<Match> = vec![Match::new(Vec::new(), start)];
        for parser in &self.parsers {
            let mut next: Vec<Match> = Vec::new();
            for prefix in &match_list {
                if let Ok(extensions) = parser.lparse(source, prefix.start) {
                    for ext in extensions {
                        let mut combined = prefix.nodes.clone();
                        combined.extend(ext.nodes);
                        next.push(Match::new(combined, ext.start));
                    }
                }
            }
            if next.is_empty() {
                return Err(ParseError::new("Concatenation", start));
            }
            match_list = next;
        }
        // Python sorts the final list longest-first before yielding.
        // We mirror that ordering here so downstream consumers see the
        // same sequence.
        sort_by_longest(&mut match_list);
        Ok(match_list)
    }
}

/// Stable sort by `start` descending — longest match first.
pub(crate) fn sort_by_longest(matches: &mut [Match]) {
    matches.sort_by_key(|m| std::cmp::Reverse(m.start));
}
