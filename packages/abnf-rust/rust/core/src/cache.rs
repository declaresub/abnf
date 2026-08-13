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
//! Entries are scoped to a single parse, and exist only while one is
//! in progress: without a `ParseScope` the cache is inert.  A `ParseScope` guard at the
//! FFI boundary bumps a thread-local epoch on entry to the outermost
//! `lparse`, and a cache whose stored epoch differs from the current
//! one is empty by definition.  One parse sees one source, so `start`
//! alone identifies a position and nothing has to be inferred about
//! the source itself.
//!
//! This replaces an earlier scheme that remembered the source's
//! `(pointer, length)` and a sampled content fingerprint.  That
//! sampled only the first and last 64 bytes, so two sources of equal
//! length differing anywhere in between — with the second landing at
//! the freed address of the first, which CPython's allocator does
//! routinely — compared equal and the second parse silently reused
//! the first one's matches.

use std::cell::Cell;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};

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
    /// Epoch these entries belong to.  `0` means "never used"; live
    /// epochs start at 1, so a fresh cache never matches.
    epoch: u64,
    pub hits: u64,
    pub misses: u64,
}

impl ParseCache {
    pub fn new(max_size: Option<usize>) -> Self {
        let inner = match max_size.and_then(NonZeroUsize::new) {
            Some(cap) => Backing::Bounded(LruCache::new(cap)),
            None => Backing::Unbounded(HashMap::new()),
        };
        Self {
            inner,
            epoch: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Discard entries belonging to an earlier parse.  Returns false
    /// when there is no parse in progress, in which case the cache
    /// must not be used at all: outside a `ParseScope` there is no
    /// boundary to scope entries to, so retaining them across calls
    /// would be the cross-source staleness this design removes.
    fn bind(&mut self) -> bool {
        if !in_parse() {
            if self.epoch != 0 {
                self.inner.reset();
                self.epoch = 0;
            }
            return false;
        }
        let now = current_epoch();
        if self.epoch != now {
            self.inner.reset();
            self.epoch = now;
        }
        true
    }

    pub fn get(&mut self, start: usize) -> Option<CachedResult> {
        if !self.bind() {
            self.misses += 1;
            return None;
        }
        if let Some(v) = self.inner.get(start) {
            self.hits += 1;
            Some(v)
        } else {
            self.misses += 1;
            None
        }
    }

    pub fn put(&mut self, start: usize, value: CachedResult) {
        if !self.bind() {
            return;
        }
        self.inner.put(start, value);
    }

    pub fn clear(&mut self) {
        self.inner.reset();
        self.epoch = 0;
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

/// Source of epoch numbers, shared by every thread.
///
/// It has to be global, not thread-local.  A `Repetition` -- and so
/// its cache -- is shared across threads behind a `Mutex`, while a
/// parse belongs to one thread.  With a per-thread counter, two
/// threads would independently reach epoch N, and the second would
/// find entries stamped N by the first and treat them as its own:
/// the same cross-source corruption this design removes, arriving by
/// a different route.  A global counter makes every parse in the
/// process distinguishable.  `Relaxed` suffices -- uniqueness is the
/// only requirement, and the `Mutex` around the cache provides the
/// happens-before edge for the entries themselves.
static EPOCH_COUNTER: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Epoch of the parse this thread is currently running, claimed
    /// from `EPOCH_COUNTER` on entry to the outermost `lparse`.
    static CURRENT_EPOCH: Cell<u64> = const { Cell::new(0) };
    /// Nesting depth, so only the *outermost* entry claims a new
    /// epoch.  A `PyCallbackParser` that re-enters the engine is part
    /// of the same parse and must keep using the same entries.
    static PARSE_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Marks the dynamic extent of one parse.  Construct at the FFI
/// boundary; entries cached inside it are discarded once a later
/// parse begins.
pub struct ParseScope {
    _private: (),
}

impl ParseScope {
    pub fn enter() -> Self {
        PARSE_DEPTH.with(|depth| {
            let current = depth.get();
            if current == 0 {
                // `fetch_add` returns the previous value; epochs start
                // at 1 so that a never-used cache (epoch 0) never
                // matches a live parse.
                let claimed = EPOCH_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
                CURRENT_EPOCH.with(|epoch| epoch.set(claimed));
            }
            depth.set(current + 1);
        });
        Self { _private: () }
    }
}

impl Drop for ParseScope {
    fn drop(&mut self) {
        PARSE_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// Marks a sub-parse over a *different* source inside the current
/// parse: rule exclusion re-parses a matched span against the
/// excluded rule.
///
/// Cache entries are keyed by position and scoped by epoch, which
/// assumes one epoch sees one source.  A sub-parse over other text
/// therefore has to claim its own epoch, or its positions would
/// collide with the enclosing parse's.  The outer epoch is restored
/// on drop; caches the sub-parse touched are reset when the outer
/// parse next reaches them, so it costs hit rate in grammars that use
/// exclusions and nothing at all in grammars that do not.
pub struct SourceScope {
    previous: u64,
}

impl SourceScope {
    pub fn enter() -> Self {
        let previous = CURRENT_EPOCH.with(Cell::get);
        let claimed = EPOCH_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
        CURRENT_EPOCH.with(|epoch| epoch.set(claimed));
        Self { previous }
    }
}

impl Drop for SourceScope {
    fn drop(&mut self) {
        CURRENT_EPOCH.with(|epoch| epoch.set(self.previous));
    }
}

/// The epoch currently being parsed under.
pub fn current_epoch() -> u64 {
    CURRENT_EPOCH.with(Cell::get)
}

/// Whether a parse is in progress on this thread.  Callers using
/// `abnf-core` directly, without a `ParseScope`, get no memoisation:
/// there is no boundary that would make entries safe to keep.
pub fn in_parse() -> bool {
    PARSE_DEPTH.with(Cell::get) > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ParseError;
    use std::sync::Arc;

    fn marker(label: &str) -> CachedResult {
        CachedResult::Failed(ParseError::new(Arc::<str>::from(label), 0))
    }

    /// Entries must not survive into the next parse.  Under the old
    /// source-fingerprint scheme this was the corruption case: two
    /// sources with identical 64-byte head and tail, the second at the
    /// freed address of the first, compared equal and shared entries.
    /// Scoping to an epoch makes the source irrelevant.
    #[test]
    fn entries_do_not_cross_parse_boundaries() {
        let mut cache = ParseCache::new(None);

        {
            let _scope = ParseScope::enter();
            cache.put(0, marker("first parse"));
            assert!(cache.get(0).is_some(), "entry visible within its own parse");
        }
        {
            let _scope = ParseScope::enter();
            assert!(
                cache.get(0).is_none(),
                "an entry from a finished parse leaked into the next one"
            );
        }
    }

    /// Within one parse, entries are reused -- that is the whole point.
    #[test]
    fn entries_are_reused_within_one_parse() {
        let mut cache = ParseCache::new(None);
        let _scope = ParseScope::enter();
        cache.put(7, marker("same parse"));
        assert!(cache.get(7).is_some());
        assert_eq!(cache.hits, 1);
    }

    /// A nested entry -- a `PyCallbackParser` re-entering the engine --
    /// is part of the same parse and must not start a new epoch.
    #[test]
    fn nested_scopes_share_one_epoch() {
        let mut cache = ParseCache::new(None);
        let _outer = ParseScope::enter();
        cache.put(3, marker("outer"));
        {
            let _inner = ParseScope::enter();
            assert!(
                cache.get(3).is_some(),
                "a nested lparse started a new epoch and discarded the outer parse's work"
            );
        }
        assert!(
            cache.get(3).is_some(),
            "outer entries survive the nested scope"
        );
    }

    /// Epochs must be unique across threads, not just within one.
    /// The cache is shared behind a `Mutex` while a parse belongs to a
    /// single thread, so a per-thread counter would let two threads
    /// both reach epoch N and read each other's entries.
    #[test]
    fn epochs_are_unique_across_threads() {
        use std::collections::HashSet;
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        let _scope = ParseScope::enter();
                        tx.send(current_epoch()).unwrap();
                    }
                })
            })
            .collect();
        drop(tx);
        for h in handles {
            h.join().unwrap();
        }
        let seen: Vec<u64> = rx.iter().collect();
        let unique: HashSet<u64> = seen.iter().copied().collect();
        assert_eq!(
            seen.len(),
            unique.len(),
            "two parses shared an epoch; entries would cross between them"
        );
        assert!(!unique.contains(&0), "epoch 0 means never parsed");
    }

    /// A cache that has never seen a parse holds nothing.
    #[test]
    fn fresh_cache_is_empty_under_a_new_epoch() {
        let mut cache = ParseCache::new(None);
        let _scope = ParseScope::enter();
        assert!(cache.get(0).is_none());
    }

    /// Outside a `ParseScope` there is no parse boundary, so the cache
    /// must not retain anything: a direct `abnf-core` caller would
    /// otherwise see one call's results answer the next one's lookup.
    #[test]
    fn cache_is_inert_outside_a_parse_scope() {
        let mut cache = ParseCache::new(None);
        cache.put(0, marker("no scope"));
        assert!(cache.get(0).is_none());
        assert_eq!(cache.len(), 0);
    }
}
