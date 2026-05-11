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

            let progressed = new_match_set.iter().any(|m| !match_set.contains(m));
            if progressed {
                match_count += 1;
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

        {
            let mut cache = self.cache.lock().expect("ParseCache mutex poisoned");
            cache.put(source, start, CachedResult::Matches(match_set.clone()));
        }
        Ok(match_set)
    }
}

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
        Self {
            value: m.value(),
            start: m.start,
        }
    }
}
