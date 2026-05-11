//! `LparseIter` — Python iterator wrapping a Rust combinator's
//! `lparse` result.
//!
//! The Python tests treat `parser.lparse(source, start)` as a
//! generator: they call `next(...)` on it, expect `ParseError` on
//! the first iteration when no match exists, and let it be consumed
//! via `set(...)` / `list(...)` for the success case.  To match
//! those semantics from Rust we materialise the match list eagerly,
//! then return a pyclass iterator that lazily yields each match (or
//! raises the stored `ParseError` once before raising
//! `StopIteration`).

use pyo3::exceptions::PyStopIteration;
use pyo3::prelude::*;

use crate::errors::parse_error_to_pyerr;
use crate::nodes::{rust_matches_to_py, PyMatch};

#[pyclass]
pub struct LparseIter {
    iter: std::vec::IntoIter<Py<PyMatch>>,
    pending_error: Option<PyErr>,
}

#[pymethods]
impl LparseIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self) -> PyResult<Py<PyMatch>> {
        if let Some(err) = self.pending_error.take() {
            return Err(err);
        }
        self.iter
            .next()
            .ok_or_else(|| PyStopIteration::new_err(()))
    }
}

/// Build an `LparseIter` from a Rust `ParseResult`.
pub fn lparse_iter(
    py: Python<'_>,
    result: abnf_core::ParseResult,
    source: &str,
) -> PyResult<Py<LparseIter>> {
    let (matches, pending_error) = match result {
        Ok(ms) => (rust_matches_to_py(py, ms, source)?, None),
        Err(e) => (Vec::new(), Some(parse_error_to_pyerr(py, e))),
    };
    Py::new(
        py,
        LparseIter {
            iter: matches.into_iter(),
            pending_error,
        },
    )
}
