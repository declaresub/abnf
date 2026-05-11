//! `Repeat` / `Repetition` — ABNF `n*m` operator.
//!
//! Mirrors `abnf.parser.Repeat` / `Repetition`
//! (`_parser_python.py:192-264`).

use std::sync::Mutex;

use crate::cache::{CachedResult, ParseCache};
use crate::concatenation::{sort_by_longest, Concatenation};
use crate::error::ParseError;
use crate::matcher::Match;
use crate::parser::{ArcParser, ParseResult};

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

    pub fn cache(&self) -> &Mutex<ParseCache> {
        &self.cache
    }

    pub fn lparse(&self, source: &str, start: usize) -> ParseResult {
        {
            let mut cache = self.cache.lock().expect("ParseCache mutex poisoned");
            if let Some(cached) = cache.get(source, start) {
                return match cached {
                    CachedResult::Matches(ms) => Ok(ms),
                    CachedResult::Failed(err) => Err(err),
                };
            }
        }

        // The repetition's match set is deduplicated by *end position*
        // (i.e. `Match.start`).  Mirroring Python's `set` semantics
        // requires `(value, start)` equality, but two matches with the
        // same starting position consume the same source span and
        // therefore have the same `value`; using `start` alone avoids
        // O(N²) cost from materialising and comparing match values.
        let mut match_set: Vec<Match> = if self.repeat.min == 0 {
            vec![Match::new(Vec::new(), start)]
        } else {
            let parsers = vec![self.element.clone(); self.repeat.min];
            let concat = Concatenation::new(parsers);
            match concat.lparse(source, start) {
                Ok(ms) => ms,
                Err(_) => {
                    let err = ParseError::new("Repetition", start);
                    let mut cache = self.cache.lock().expect("ParseCache mutex poisoned");
                    cache.put(source, start, CachedResult::Failed(err.clone()));
                    return Err(err);
                }
            }
        };
        let mut seen_starts: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        match_set.retain(|m| seen_starts.insert(m.start));
        let mut last_match_set = match_set.clone();
        let mut match_count = self.repeat.min;

        loop {
            if let Some(max) = self.repeat.max {
                if match_count == max {
                    break;
                }
            }
            let mut new_match_set: Vec<Match> = Vec::new();
            for prefix in last_match_set.drain(..) {
                let extensions = match self.element.lparse(source, prefix.start) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                // Filter out extensions whose end position is already
                // covered, then iterate.  We move `prefix.nodes` into
                // the last surviving extension and clone for the rest.
                let mut surviving: Vec<Match> = extensions
                    .into_iter()
                    .filter(|ext| !seen_starts.contains(&ext.start))
                    .collect();
                if surviving.is_empty() {
                    continue;
                }
                let last = surviving.pop().expect("non-empty checked above");
                for ext in surviving {
                    let mut combined = prefix.nodes.clone();
                    combined.extend(ext.nodes);
                    new_match_set.push(Match::new(combined, ext.start));
                }
                let mut combined = prefix.nodes;
                combined.extend(last.nodes);
                new_match_set.push(Match::new(combined, last.start));
            }
            // De-dupe within new_match_set by end position.
            let mut local_seen: std::collections::HashSet<usize> =
                std::collections::HashSet::new();
            new_match_set.retain(|m| local_seen.insert(m.start));

            if new_match_set.is_empty() {
                break;
            }
            match_count += 1;
            for m in &new_match_set {
                seen_starts.insert(m.start);
            }
            match_set.extend(new_match_set.iter().cloned());
            last_match_set = new_match_set;
        }

        sort_by_longest(&mut match_set);

        {
            let mut cache = self.cache.lock().expect("ParseCache mutex poisoned");
            cache.put(source, start, CachedResult::Matches(match_set.clone()));
        }
        Ok(match_set)
    }
}
