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
        // Fast path: same source object as last call.  Verify content
        // didn't change underneath us — Python sometimes places a
        // different string at a freed address with the same length,
        // and the sampled fingerprint catches that.
        if self.bound_token == Some(token) {
            let fingerprint = content_fingerprint(source);
            if self.bound_hash == Some(fingerprint) {
                return;
            }
            self.inner.reset();
            self.bound_hash = Some(fingerprint);
            return;
        }
        // Different source buffer: always reset.  Cached `Match`
        // objects embed byte offsets and `Arc<str>` snapshots that
        // belong to the previous source; reusing them across distinct
        // sources is incorrect even when the contents happen to
        // fingerprint the same.  Skipping the reset on fingerprint
        // collision (H1) caused silent cross-source corruption.
        self.inner.reset();
        self.bound_token = Some(token);
        self.bound_hash = Some(content_fingerprint(source));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ParseError;
    use std::sync::Arc;

    /// H1 regression: two distinct sources whose 64-byte head and
    /// 64-byte tail are identical produce the same `content_fingerprint`
    /// but must NOT share cache entries.  Cached `Match` objects embed
    /// byte offsets and `Arc<str>` values tied to a specific source;
    /// reusing them across distinct source buffers is silent corruption.
    #[test]
    fn token_mismatch_invalidates_cache_even_on_fingerprint_collision() {
        let head: String = "A".repeat(64);
        let tail: String = "D".repeat(64);
        let s1 = format!("{head}BC{tail}");
        let s2 = format!("{head}XY{tail}");
        assert_eq!(s1.len(), s2.len());
        assert_eq!(content_fingerprint(&s1), content_fingerprint(&s2));
        assert_ne!(s1.as_ptr(), s2.as_ptr());

        let mut cache = ParseCache::new(None);
        let marker = CachedResult::Failed(ParseError::new(
            Arc::<str>::from("from-s1"),
            64,
        ));
        cache.put(&s1, 64, marker);
        assert_eq!(cache.len(), 1, "entry should be installed against s1");

        // The lookup against s2 must miss: distinct source objects
        // with colliding fingerprints share a token mismatch and that
        // alone must reset the cache.
        let hit = cache.get(&s2, 64);
        assert!(
            hit.is_none(),
            "stale s1 entry leaked into a lookup against s2 \
             (fingerprint collision was treated as identity)"
        );
    }

    /// Sanity-check the inverse: same source object across two calls
    /// reuses the cache.
    #[test]
    fn same_source_reuses_cache() {
        let s = "hello world".to_string();
        let mut cache = ParseCache::new(None);
        let marker = CachedResult::Failed(ParseError::new(
            Arc::<str>::from("static"),
            0,
        ));
        cache.put(&s, 0, marker);
        assert!(cache.get(&s, 0).is_some());
    }
}
