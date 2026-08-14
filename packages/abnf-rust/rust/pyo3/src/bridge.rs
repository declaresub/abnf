//! Python `Rule` ↔ Rust `NamedRule` registry.
//!
//! Each Python `Rule` instance maps to exactly one Rust `NamedRule`
//! handle.  The registry lets `extract_parser` substitute the
//! handle for the Python object when a Rule appears as a combinator
//! child, so parsing dispatches purely through Rust instead of
//! round-tripping through Python on every rule reference.  This is
//! the main optimisation that lets the Rust backend beat the
//! pure-Python implementation; without it, every `DIGIT` /
//! `ALPHA` / etc. lookup pays the GIL + marshalling cost.
//!
//! The key is the Python object's pointer.  `Rule._obj_map` keeps
//! every Rule alive for the lifetime of its class, so pointers are
//! stable -- and that immortality is load-bearing, not incidental.
//! Were a `Rule` ever collected, the allocator could hand its address
//! to a new `Rule`, which would then silently inherit the dead rule's
//! compiled tree from this map.
//!
//! There is deliberately no operation to clear or prune the registry.
//! A `clear_bridge()` existed until issue #187: because a rule's
//! compiled tree embeds the `Arc<NamedRule>` handles of the rules it
//! references, dropping the map does not free those trees -- it only
//! desynchronises the two sides.  Rules defined afterwards look up
//! `ALPHA`, `DIGIT` and friends, find nothing, and build fresh empty
//! handles, so the grammar rejects valid input; and redefining an
//! existing rule writes to an orphan while live trees keep the old
//! handle.  Nor would clearing reclaim much: the Python side retains
//! roughly a third of the per-rule cost in `_obj_map` regardless.
//! Registry growth is a function of rules created, and is documented
//! in `docs/how-to/use-the-rust-backend.md`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;
use pyo3::prelude::*;

use abnf_core::NamedRule;

static BRIDGE: Lazy<Mutex<HashMap<usize, Arc<NamedRule>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Get the `NamedRule` handle for a Python `Rule`, creating an
/// undefined placeholder if none exists yet.  Multiple lookups for
/// the same Python Rule return the same handle, so forward
/// references resolve correctly once the definition arrives via
/// [`set_definition_for`].
pub fn get_or_create(py_rule: &Bound<'_, PyAny>) -> PyResult<Arc<NamedRule>> {
    let id = py_rule.as_ptr() as usize;
    // Tolerate a poisoned lock: the registry is a cache mapping
    // Python `Rule` ids → Rust `NamedRule` handles, with no
    // cross-entry invariants.  A panic in an earlier caller can leave
    // the lock poisoned, but the data is still a valid `HashMap`.
    let mut guard = BRIDGE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = guard.get(&id) {
        return Ok(existing.clone());
    }
    let name: String = py_rule.getattr("name")?.extract()?;
    let handle = Arc::new(NamedRule::new(name));
    guard.insert(id, handle.clone());
    Ok(handle)
}

/// Replace (or set) the definition of the `NamedRule` for `py_rule`.
/// Invoked by the `Rule._set_definition_hook` callback so the Rust
/// shadow registry always reflects the current Python-side
/// definition graph.  The `definition` argument is any Python value
/// that [`crate::parsers::extract_parser`] can convert to an
/// `ArcParser` (typically a Rust-backed combinator pyclass).
pub fn set_definition_for(
    py_rule: &Bound<'_, PyAny>,
    parser: abnf_core::ArcParser,
) -> PyResult<()> {
    let handle = get_or_create(py_rule)?;
    handle.set_definition(parser);
    Ok(())
}

/// Point the `NamedRule` for `py_rule` at the `NamedRule` for
/// `py_excluded`, so the engine applies `Rule.exclude_rule` to nested
/// rule references.  Before this, the exclusion lived only in the
/// pure-Python `Rule.lparse`, which the Rust path enters just once
/// per parse -- for the top-level rule -- so a nested exclusion was
/// silently ignored and the grammar accepted what it was written to
/// reject (issue #179).
pub fn set_exclude_for(
    py_rule: &Bound<'_, PyAny>,
    py_excluded: Option<&Bound<'_, PyAny>>,
) -> PyResult<()> {
    let handle = get_or_create(py_rule)?;
    let excluded = match py_excluded {
        Some(rule) => Some(get_or_create(rule)?),
        None => None,
    };
    handle.set_exclude(excluded);
    Ok(())
}

/// Current size of the bridge registry.  Primarily useful in tests
/// and diagnostics; not part of the public API contract.
#[pyfunction]
pub fn bridge_size() -> usize {
    let guard = BRIDGE.lock().unwrap_or_else(|e| e.into_inner());
    guard.len()
}
