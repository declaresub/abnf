//! PyO3 bindings exposing the `abnf-core` engine to Python.
//!
//! The compiled module appears as `abnf_rust._ext`; the Python package
//! wrapper in `src/abnf_rust/__init__.py` re-exports its symbols.
//!
//! This file is currently a placeholder so the wheel builds cleanly;
//! the combinator pyclasses land in a subsequent phase.

use pyo3::prelude::*;

#[pymodule]
fn _ext(_py: Python<'_>, _m: &Bound<'_, PyModule>) -> PyResult<()> {
    Ok(())
}
