//! `Alternation` — ABNF `/` operator.
//!
//! Mirrors `abnf.parser.Alternation` (`_parser_python.py:126-154`).
//!
//! Two modes governed by `first_match`:
//!
//! * `false` (default): collect matches from every successful
//!   alternative.  The caller (typically `Rule.parse`) re-orders by
//!   longest match.
//! * `true`: yield matches from the first successful alternative and
//!   stop scanning the remaining ones.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::ParseError;
use crate::matcher::Match;
use crate::parser::{ArcParser, ParseResult};

#[derive(Debug)]
pub struct Alternation {
    pub parsers: Vec<ArcParser>,
    first_match: AtomicBool,
}

impl Alternation {
    pub fn new(parsers: Vec<ArcParser>) -> Self {
        Self {
            parsers,
            first_match: AtomicBool::new(false),
        }
    }

    pub fn with_first_match(parsers: Vec<ArcParser>, first_match: bool) -> Self {
        Self {
            parsers,
            first_match: AtomicBool::new(first_match),
        }
    }

    pub fn first_match(&self) -> bool {
        self.first_match.load(Ordering::Relaxed)
    }

    pub fn set_first_match(&self, value: bool) {
        self.first_match.store(value, Ordering::Relaxed);
    }

    pub fn lparse(&self, source: &str, start: usize) -> ParseResult {
        let mut all: Vec<Match> = Vec::new();
        let mut found = false;
        let first_match = self.first_match();
        for p in &self.parsers {
            match p.lparse(source, start) {
                Ok(ms) => {
                    if !ms.is_empty() {
                        found = true;
                    }
                    all.extend(ms);
                }
                Err(_) => continue,
            }
            // Mirror Python: in first_match mode, return after the
            // first parser that did NOT raise, regardless of whether
            // it yielded any matches.
            if first_match {
                return if found {
                    Ok(all)
                } else {
                    Ok(Vec::new())
                };
            }
        }
        if found {
            Ok(all)
        } else {
            Err(ParseError::new("Alternation", start))
        }
    }
}
