//! `Repeat` / `Repetition` — ABNF `n*m` operator.
//!
//! Mirrors `abnf.parser.Repeat` / `Repetition`
//! (`_parser_python.py:192-264`).

use std::collections::HashSet;
use std::sync::Mutex;

use smallvec::{smallvec, SmallVec};

use crate::cache::{CachedResult, ParseCache};
use crate::concatenation::{sort_by_longest, Concatenation};
use crate::error::ParseError;
use crate::matcher::Match;
use crate::parser::{ArcParser, MatchList, NodeList, ParseResult};

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

        let mut match_set: MatchList = if self.repeat.min == 0 {
            smallvec![Match::new(SmallVec::new(), start)]
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
        let mut seen_starts: HashSet<usize> = HashSet::new();
        match_set.retain(|m| seen_starts.insert(m.start));
        let mut last_match_set = match_set.clone();
        let mut match_count = self.repeat.min;

        loop {
            if let Some(max) = self.repeat.max {
                if match_count == max {
                    break;
                }
            }
            let mut new_match_set: MatchList = SmallVec::new();
            for prefix in last_match_set.drain(..) {
                let extensions = match self.element.lparse(source, prefix.start) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for ext in extensions {
                    if seen_starts.contains(&ext.start) {
                        continue;
                    }
                    let prefix_len = prefix.nodes.len();
                    let ext_len = ext.nodes.len();
                    let mut combined: NodeList = SmallVec::with_capacity(prefix_len + ext_len);
                    combined.extend(prefix.nodes.iter().cloned());
                    combined.extend(ext.nodes);
                    new_match_set.push(Match::new(combined, ext.start));
                }
            }
            let mut local_seen: HashSet<usize> = HashSet::new();
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

        if match_set.len() > 1 {
            sort_by_longest(&mut match_set);
        }

        {
            let mut cache = self.cache.lock().expect("ParseCache mutex poisoned");
            cache.put(source, start, CachedResult::Matches(match_set.clone()));
        }
        Ok(match_set)
    }
}
