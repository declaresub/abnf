//! `LparseIter` — Python iterator wrapping a Rust combinator's
//! `lparse` result.
//!
//! Materialisation is lazy: the Rust `Vec<Match>` is stored
//! verbatim and each `__next__` call converts one match into its
//! Python pyclass representation.  Callers that only need the
//! longest match (e.g. `Rule.parse`) pay for just one
//! materialisation instead of all of them; on ambiguous grammars
//! like RFC 3986 URI this avoids dozens of throwaway tree builds
//! per parse.

use pyo3::exceptions::PyStopIteration;
use pyo3::prelude::*;
use smallvec::SmallVec;

use abnf_core::Match;

use crate::errors::parse_error_to_pyerr;
use crate::nodes::PyMatch;

#[pyclass]
pub struct LparseIter {
    matches: smallvec::IntoIter<[Match; 1]>,
    /// Reference-counted source kept alive for the duration of
    /// iteration so the literal-value `Arc<str>`s remain valid.
    source: std::sync::Arc<str>,
    pending_error: Option<PyErr>,
}

#[pymethods]
impl LparseIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self, py: Python<'_>) -> PyResult<Py<PyMatch>> {
        if let Some(err) = self.pending_error.take() {
            return Err(err);
        }
        match self.matches.next() {
            Some(m) => Py::new(py, PyMatch::from_rust(py, &m, &self.source)?),
            None => Err(PyStopIteration::new_err(())),
        }
    }
}

/// Build an `LparseIter` from a Rust `ParseResult`.
pub fn lparse_iter(
    py: Python<'_>,
    result: abnf_core::ParseResult,
    source: &str,
) -> PyResult<Py<LparseIter>> {
    let (matches, pending_error) = match result {
        Ok(ms) => (ms, None),
        Err(e) => (SmallVec::new(), Some(parse_error_to_pyerr(py, e, source))),
    };
    Py::new(
        py,
        LparseIter {
            matches: matches.into_iter(),
            source: std::sync::Arc::from(source),
            pending_error,
        },
    )
}
