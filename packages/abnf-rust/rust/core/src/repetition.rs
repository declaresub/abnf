//! `Repeat` / `Repetition` — ABNF `n*m` operator.
//!
//! Mirrors `abnf.parser.Repeat` and `abnf.parser.Repetition`
//! (`_parser_python.py:192-264`).
//!
//! Algorithm:
//!
//! 1. If `min == 0`, seed with the empty match at `start`; otherwise
//!    enumerate matches of `Concatenation(element, ..., element)` of
//!    length `min`.
//! 2. Iteratively extend the current match-set by one more application
//!    of `element` until either `max` is reached or extending no
//!    longer produces matches outside the accumulated set.
//! 3. Yield the union, longest-first.
//!
//! Caching: the per-instance `ParseCache` short-circuits re-entry at
//! the same `(source, start)`.

use std::sync::Mutex;

use crate::cache::{CachedResult, ParseCache};
use crate::concatenation::{Concatenation, sort_by_longest};
use crate::error::ParseError;
use crate::matcher::Match;
use crate::parser::{ArcParser, ParseResult, ParserOp};

#[derive(Debug, Clone, Copy)]
pub struct Repeat {
    pub min: usize,
    pub max: Option<usize>,
}

impl Repeat {
    pub fn new(min: usize, max: Option<usize>) -> Self {
        Self { min, max }
    }
}

#[derive(Debug)]
pub struct Repetition {
    pub repeat: Repeat,
    pub element: ArcParser,
    cache: Mutex<ParseCache>,
}

impl Repetition {
    pub fn new(repeat: Repeat, element: ArcParser) -> Self {
        Self {
            repeat,
            element,
            cache: Mutex::new(ParseCache::default()),
        }
    }

    /// Visible for tests; returns the per-instance cache.
    pub fn cache(&self) -> &Mutex<ParseCache> {
        &self.cache
    }
}

impl ParserOp for Repetition {
    fn lparse(&self, source: &str, start: usize) -> ParseResult {
        // Check cache first.
        {
            let mut cache = self.cache.lock().expect("ParseCache mutex poisoned");
            if let Some(cached) = cache.get(source, start) {
                return match cached {
                    CachedResult::Matches(ms) => Ok(ms),
                    CachedResult::Failed(err) => Err(err),
                };
            }
        }

        // Seed.  If min == 0, the empty match at `start` is the seed;
        // otherwise we run a concatenation of `element` repeated `min`
        // times and use its output as the seed.
        let mut match_set: Vec<Match> = if self.repeat.min == 0 {
            vec![Match::new(Vec::new(), start)]
        } else {
            let parsers = vec![self.element.clone(); self.repeat.min];
            let concat = Concatenation::new(parsers);
            match concat.lparse(source, start) {
                Ok(ms) => ms,
                Err(_) => {
                    // Cache the failure as Python does, then re-raise.
                    let err = ParseError::new("Repetition", start);
                    let mut cache = self.cache.lock().expect("ParseCache mutex poisoned");
                    cache.put(source, start, CachedResult::Failed(err.clone()));
                    return Err(err);
                }
            }
        };
        // De-duplicate (Python uses a set for `match_set`).
        dedupe(&mut match_set);
        let mut last_match_set = match_set.clone();
        let mut match_count = self.repeat.min;

        loop {
            if let Some(max) = self.repeat.max {
                if match_count == max {
                    break;
                }
            }
            let mut new_match_set: Vec<Match> = Vec::new();
            for prefix in &last_match_set {
                if let Ok(extensions) = self.element.lparse(source, prefix.start) {
                    for ext in extensions {
                        let mut combined = prefix.nodes.clone();
                        combined.extend(ext.nodes);
                        new_match_set.push(Match::new(combined, ext.start));
                    }
                }
            }
            dedupe(&mut new_match_set);

            // Python: `if not new_match_set <= match_set: continue
            // accumulating; else stop`.  In other words, stop when every
            // new match is already in match_set.
            let progressed = new_match_set
                .iter()
                .any(|m| !match_set.contains(m));
            if progressed {
                match_count += 1;
                // match_set |= new_match_set
                for m in &new_match_set {
                    if !match_set.contains(m) {
                        match_set.push(m.clone());
                    }
                }
                last_match_set = new_match_set;
            } else {
                break;
            }
        }

        sort_by_longest(&mut match_set);

        // Cache the result.
        {
            let mut cache = self.cache.lock().expect("ParseCache mutex poisoned");
            cache.put(source, start, CachedResult::Matches(match_set.clone()));
        }
        Ok(match_set)
    }
}

/// De-duplicate a `Vec<Match>` while preserving first-occurrence order.
/// Equivalent to Python's `set(...)` over the same iterable for our
/// `Match` (whose `Eq`/`Hash` are content-based).
fn dedupe(matches: &mut Vec<Match>) {
    use std::collections::HashSet;
    let mut seen: HashSet<MatchKey> = HashSet::new();
    matches.retain(|m| seen.insert(MatchKey::from(m)));
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct MatchKey {
    value: String,
    start: usize,
}

impl MatchKey {
    fn from(m: &Match) -> Self {
        Self { value: m.value(), start: m.start }
    }
}
