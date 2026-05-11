//! PyO3 bindings exposing the `abnf-core` engine to Python.
//!
//! The compiled module appears as ``abnf_rust._ext``; the Python
//! package wrapper in `src/abnf_rust/__init__.py` re-exports its
//! symbols.

mod bootstrap;
mod bridge;
mod errors;
mod external;
mod hooks;
mod iter;
mod nodes;
mod parsers;

use pyo3::prelude::*;

#[pymodule]
fn _ext(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Combinators
    m.add_class::<parsers::PyAlternation>()?;
    m.add_class::<parsers::PyConcatenation>()?;
    m.add_class::<parsers::PyRepetition>()?;
    m.add_class::<parsers::PyOption>()?;
    m.add_class::<parsers::PyLiteral>()?;
    m.add_class::<parsers::PyProse>()?;
    m.add_class::<parsers::PyRepeat>()?;

    // Parse tree
    m.add_class::<nodes::PyMatch>()?;
    m.add_class::<nodes::PyNode>()?;
    m.add_class::<nodes::PyLiteralNode>()?;

    // Functions
    m.add_function(wrap_pyfunction!(bootstrap::bootstrap, m)?)?;
    m.add_function(wrap_pyfunction!(hooks::set_definition_hook, m)?)?;

    Ok(())
}
