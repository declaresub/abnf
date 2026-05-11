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
//! stable.

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
    let mut guard = BRIDGE.lock().expect("BRIDGE poisoned");
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
