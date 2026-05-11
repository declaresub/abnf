//! Python-callable hooks installed by the dispatch shim.
//!
//! When the Rust backend is active, the dispatch shim wires
//! [`set_definition_hook`] onto `Rule._set_definition_hook` so that
//! every `rule.definition = value` write keeps the Rust shadow
//! registry of `NamedRule` handles in sync.

use pyo3::prelude::*;

use crate::bridge::set_definition_for;
use crate::parsers::extract_parser;

#[pyfunction]
pub fn set_definition_hook(
    rule: &Bound<'_, PyAny>,
    definition: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let parser = extract_parser(definition)?;
    set_definition_for(rule, parser)?;
    Ok(())
}
