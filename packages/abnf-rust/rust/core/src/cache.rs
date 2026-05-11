//! `ParseCache` — cache used by `Repetition`.
//!
//! Mirrors `abnf.parser.ParseCache`: stores either the match-set
//! produced at a given start position or the `ParseError` raised
//! there; on a cache hit `Repetition` short-circuits the recursive
//! work.
//!
//! Two backing implementations behind a single interface:
//!
//! * `max_size = None` (Python default) → unbounded `HashMap`.
//! * `max_size = Some(n)` → `LruCache` with capacity `n`.
//!
//! The Python key is `(source, start)` (string-equality on the
//! source).  We approximate that by remembering the most recent
//! source's `(pointer, length)` and clearing the cache whenever it
//! changes — equivalent to Python's behaviour when the same source
//! object is reused across calls, and cheaply correct when it is not.

use std::collections::HashMap;
use std::num::NonZeroUsize;

use lru::LruCache;

use crate::error::ParseError;
use crate::matcher::Match;

#[derive(Debug, Clone)]
pub enum CachedResult {
    Matches(Vec<Match>),
    Failed(ParseError),
}

#[derive(Debug)]
enum Backing {
    Unbounded(HashMap<usize, CachedResult>),
    Bounded(LruCache<usize, CachedResult>),
}

impl Backing {
    fn get(&mut self, key: usize) -> Option<CachedResult> {
        match self {
            Backing::Unbounded(m) => m.get(&key).cloned(),
            Backing::Bounded(c) => c.get(&key).cloned(),
        }
    }

    fn put(&mut self, key: usize, value: CachedResult) {
        match self {
            Backing::Unbounded(m) => {
                m.insert(key, value);
            }
            Backing::Bounded(c) => {
                c.put(key, value);
            }
        }
    }

    fn clear(&mut self) {
        match self {
            Backing::Unbounded(m) => m.clear(),
            Backing::Bounded(c) => c.clear(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Backing::Unbounded(m) => m.len(),
            Backing::Bounded(c) => c.len(),
        }
    }
}

#[derive(Debug)]
pub struct ParseCache {
    inner: Backing,
    bound: Option<(*const u8, usize)>,
    pub hits: u64,
    pub misses: u64,
}

// SAFETY: the only raw pointer held is `bound`, a `(ptr, len)` token
// used purely for equality comparisons against the next source
// passed in.  It is never dereferenced and never outlives the call
// that produced it once the cache is cleared.
unsafe impl Send for ParseCache {}
unsafe impl Sync for ParseCache {}

impl ParseCache {
    pub fn new(max_size: Option<usize>) -> Self {
        let inner = match max_size.and_then(NonZeroUsize::new) {
            Some(cap) => Backing::Bounded(LruCache::new(cap)),
            None => Backing::Unbounded(HashMap::new()),
        };
        Self { inner, bound: None, hits: 0, misses: 0 }
    }

    fn bind(&mut self, source: &str) {
        let token = (source.as_ptr(), source.len());
        if self.bound != Some(token) {
            self.inner.clear();
            self.bound = Some(token);
        }
    }

    pub fn get(&mut self, source: &str, start: usize) -> Option<CachedResult> {
        self.bind(source);
        if let Some(v) = self.inner.get(start) {
            self.hits += 1;
            Some(v)
        } else {
            self.misses += 1;
            None
        }
    }

    pub fn put(&mut self, source: &str, start: usize, value: CachedResult) {
        self.bind(source);
        self.inner.put(start, value);
    }

    pub fn clear(&mut self) {
        self.inner.clear();
        self.bound = None;
        self.hits = 0;
        self.misses = 0;
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.len() == 0
    }
}

impl Default for ParseCache {
    fn default() -> Self {
        Self::new(None)
    }
}
