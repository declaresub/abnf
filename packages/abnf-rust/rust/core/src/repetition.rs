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
            // Tolerate a poisoned mutex: a panic in some unrelated
            // earlier code path must not permanently brick this rule.
            // The cache is purely a hit-rate optimisation; stale
            // entries left over by a poisoned holder only cost us a
            // miss on the next lookup.
            let mut cache = self
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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
                    // Tolerate a poisoned mutex: a panic in some unrelated
            // earlier code path must not permanently brick this rule.
            // The cache is purely a hit-rate optimisation; stale
            // entries left over by a poisoned holder only cost us a
            // miss on the next lookup.
            let mut cache = self
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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
            // Tolerate a poisoned mutex: a panic in some unrelated
            // earlier code path must not permanently brick this rule.
            // The cache is purely a hit-rate optimisation; stale
            // entries left over by a poisoned holder only cost us a
            // miss on the next lookup.
            let mut cache = self
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cache.put(source, start, CachedResult::Matches(match_set.clone()));
        }
        Ok(match_set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::literal::Literal;
    use crate::parser::{arc, Parser};

    /// M6 regression: after the cache mutex is poisoned by a panic
    /// somewhere up the stack, subsequent `Repetition::lparse` calls
    /// must still be able to acquire the lock and proceed.  The
    /// pre-fix code used `.expect("...")` on lock acquisition, which
    /// permanently bricked the parser for the rest of the process.
    /// The fix replaces it with `unwrap_or_else(|e| e.into_inner())`
    /// so a poisoned lock is treated as merely "the previous holder
    /// may have left stale state" — acceptable for our cache, since
    /// stale entries only cause false misses on subsequent lookups.
    #[test]
    fn poisoned_cache_lock_recovers() {
        let element = arc(Parser::Literal(Literal::string("x", false)));
        let parser = Repetition::new(Repeat::new(1, None), element);

        // Force-poison the cache mutex by panicking while holding it.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = parser.cache().lock().unwrap();
            panic!("force-poison");
        }));
        assert!(
            parser.cache().is_poisoned(),
            "test setup failed to poison the mutex"
        );

        // Pre-fix this would panic with "ParseCache mutex poisoned".
        // Post-fix the parse succeeds.
        let result = parser.lparse("xxx", 0);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }
}
