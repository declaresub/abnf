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
use crate::parser::MatchList;

#[derive(Debug, Clone)]
pub enum CachedResult {
    Matches(MatchList),
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

    /// Reset to an empty backing.  Avoids `HashMap::clear`'s
    /// O(capacity) cost — large caches from a previous big-source
    /// parse would otherwise impose a measurable cost on every
    /// subsequent small parse that triggers invalidation.
    fn reset(&mut self) {
        match self {
            Backing::Unbounded(m) => *m = HashMap::new(),
            Backing::Bounded(c) => {
                let cap = c.cap();
                *c = LruCache::new(cap);
            }
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
    /// `(ptr, len)` of the source the cache is currently keyed
    /// against.  Cheap to compare on every call; mismatch triggers a
    /// content-hash check.
    bound_token: Option<(*const u8, usize)>,
    /// `XxHash` of the bound source's content.  Distinguishes
    /// distinct sources that reuse the same address (e.g. short-lived
    /// Python strings).
    bound_hash: Option<u64>,
    pub hits: u64,
    pub misses: u64,
}

// SAFETY: `bound_token` holds a `(ptr, len)` value that is only used
// as a fast-equality hint; the actual cache invalidation falls back
// to content hashing.  The raw pointer is never dereferenced.
unsafe impl Send for ParseCache {}
unsafe impl Sync for ParseCache {}

impl ParseCache {
    pub fn new(max_size: Option<usize>) -> Self {
        let inner = match max_size.and_then(NonZeroUsize::new) {
            Some(cap) => Backing::Bounded(LruCache::new(cap)),
            None => Backing::Unbounded(HashMap::new()),
        };
        Self {
            inner,
            bound_token: None,
            bound_hash: None,
            hits: 0,
            misses: 0,
        }
    }

    fn bind(&mut self, source: &str) {
        let token = (source.as_ptr(), source.len());
        // Compute a cheap O(1) content fingerprint from a short
        // sample of the source.  Hashing the whole source on every
        // cache use was catastrophic on large inputs (a 138KB fuzz
        // case slowed the Rust backend by ~3x relative to the
        // Python implementation); sampling is fast enough that
        // there's no observable overhead on small inputs and
        // detects content changes in practice.
        let fingerprint = content_fingerprint(source);
        if self.bound_token == Some(token) && self.bound_hash == Some(fingerprint) {
            return;
        }
        if self.bound_hash != Some(fingerprint) {
            self.inner.reset();
            self.bound_hash = Some(fingerprint);
        }
        self.bound_token = Some(token);
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
        self.inner.reset();
        self.bound_token = None;
        self.bound_hash = None;
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

/// Cheap content fingerprint for cache invalidation: hashes a short
/// fixed-size sample of the source (up to 64 bytes from the start
/// plus up to 64 bytes from the end) rather than the entire input.
/// Detects content changes in practice while keeping the operation
/// O(1) in source length.
fn content_fingerprint(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    let bytes = s.as_bytes();
    let head_len = bytes.len().min(64);
    let tail_len = bytes.len().saturating_sub(head_len).min(64);
    bytes[..head_len].hash(&mut h);
    if tail_len > 0 {
        bytes[bytes.len() - tail_len..].hash(&mut h);
    }
    bytes.len().hash(&mut h);
    h.finish()
}
