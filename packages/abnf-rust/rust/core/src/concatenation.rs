//! `Concatenation` — sequence operator.
//!
//! Mirrors `abnf.parser.Concatenation` (`_parser_python.py:157-189`).

use smallvec::{smallvec, SmallVec};

use crate::error::ParseError;
use crate::matcher::Match;
use crate::parser::{ArcParser, MatchList, NodeList, ParseResult};

#[derive(Debug)]
pub struct Concatenation {
    pub parsers: Vec<ArcParser>,
}

impl Concatenation {
    pub fn new(parsers: Vec<ArcParser>) -> Self {
        Self { parsers }
    }

    pub fn lparse(&self, source: &str, start: usize) -> ParseResult {
        let mut match_list: MatchList = smallvec![Match::new(SmallVec::new(), start)];
        for parser in &self.parsers {
            let mut next: MatchList = SmallVec::new();
            // Consume `match_list` by value so the last extension of
            // each prefix can move — instead of clone — the prefix
            // nodes.  For deterministic grammars (one extension per
            // prefix, the common case), this saves one allocation
            // per concatenation step per surviving prefix.
            for prefix in match_list.drain(..) {
                let extensions = match parser.lparse(source, prefix.start) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                if extensions.is_empty() {
                    continue;
                }
                let mut iter = extensions.into_iter();
                // Take the last extension separately so we can move
                // (rather than clone) `prefix.nodes` into it.
                let last = iter
                    .next_back()
                    .expect("non-empty checked above");
                let prefix_len = prefix.nodes.len();
                for ext in iter {
                    let ext_len = ext.nodes.len();
                    let mut combined: NodeList = SmallVec::with_capacity(prefix_len + ext_len);
                    combined.extend(prefix.nodes.iter().cloned());
                    combined.extend(ext.nodes);
                    next.push(Match::new(combined, ext.start));
                }
                let last_len = last.nodes.len();
                let mut combined = prefix.nodes;
                combined.reserve(last_len);
                combined.extend(last.nodes);
                next.push(Match::new(combined, last.start));
            }
            if next.is_empty() {
                return Err(ParseError::new("Concatenation", start));
            }
            match_list = next;
        }
        if match_list.len() > 1 {
            sort_by_longest(&mut match_list);
        }
        Ok(match_list)
    }
}

/// Stable sort by `start` descending — longest match first.
pub(crate) fn sort_by_longest(matches: &mut [Match]) {
    matches.sort_by_key(|m| std::cmp::Reverse(m.start));
}
