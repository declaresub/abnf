//! `Concatenation` — sequence operator.
//!
//! Mirrors `abnf.parser.Concatenation` (`_parser_python.py:157-189`).

use crate::error::ParseError;
use crate::matcher::Match;
use crate::parser::{ArcParser, ParseResult};

#[derive(Debug)]
pub struct Concatenation {
    pub parsers: Vec<ArcParser>,
}

impl Concatenation {
    pub fn new(parsers: Vec<ArcParser>) -> Self {
        Self { parsers }
    }

    pub fn lparse(&self, source: &str, start: usize) -> ParseResult {
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
        sort_by_longest(&mut match_list);
        Ok(match_list)
    }
}

/// Stable sort by `start` descending — longest match first.
pub(crate) fn sort_by_longest(matches: &mut [Match]) {
    matches.sort_by_key(|m| std::cmp::Reverse(m.start));
}
