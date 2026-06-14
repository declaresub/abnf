//! `ExternalParser` impl that bridges a Python parser object into the
//! Rust combinator engine.
//!
//! Used by `extract_parser` whenever a Python value passed as a
//! combinator child is not itself one of our Rust-backed pyclasses
//! (e.g. a Python `Rule` instance produced by the meta-grammar
//! visitor).  Each `lparse` call re-acquires the GIL, invokes the
//! wrapped object's `lparse` method, and marshals the resulting
//! match list back into Rust.

use pyo3::prelude::*;
use pyo3::types::PyType;
use smallvec::SmallVec;

use abnf_core::{ExternalParser, ParseError, ParseResult};

use crate::nodes::py_match_to_rust;
use crate::recursion::propagate_pyerr;

#[derive(Debug)]
pub struct PyCallbackParser {
    obj: Py<PyAny>,
    /// A short description (used to populate `ParseError.parser` when
    /// the Python side raises).
    description: std::sync::Arc<str>,
}

impl PyCallbackParser {
    pub fn new(obj: Py<PyAny>, description: impl Into<std::sync::Arc<str>>) -> Self {
        Self {
            obj,
            description: description.into(),
        }
    }
}

impl ExternalParser for PyCallbackParser {
    fn lparse(&self, source: &str, start: usize) -> ParseResult {
        Python::attach(|py| -> ParseResult {
            // The Rust core hands us a byte offset; the Python parser
            // expects a code-point offset.  The translation is also
            // inverted on the way back in `py_match_to_rust`.
            let cp_start = crate::offset::byte_to_cp(source, start);
            let bound = self.obj.bind(py);
            let result = match bound.call_method1("lparse", (source, cp_start)) {
                Ok(r) => r,
                Err(e) => return Err(handle_pyerr(py, e, &self.description, start)),
            };
            let iter = match result.try_iter() {
                Ok(it) => it,
                Err(e) => return Err(handle_pyerr(py, e, &self.description, start)),
            };
            let mut matches: abnf_core::MatchList = SmallVec::new();
            for item in iter {
                let item = match item {
                    Ok(it) => it,
                    Err(e) => return Err(handle_pyerr(py, e, &self.description, start)),
                };
                let m = match py_match_to_rust(&item, source) {
                    Ok(m) => m,
                    Err(e) => return Err(handle_pyerr(py, e, &self.description, start)),
                };
                matches.push(m);
            }
            Ok(matches)
        })
    }
}

/// Decide whether a `PyErr` raised by the wrapped Python callback
/// represents a `ParseError` (handle as normal backtracking) or
/// something else (propagate to the Python caller verbatim).
///
/// Mirrors the pure-Python reference, which only catches `ParseError`;
/// any other exception bubbles uncaught through `except ParseError`
/// clauses and so should bubble uncaught through `Alternation` /
/// `Repetition` backtracking on the Rust side as well.
///
/// The `propagate_pyerr` arm diverges (panics) to thread the `PyErr`
/// up to the next `call_lparse` boundary, where it's re-raised as the
/// final result of the Python-facing `lparse(...)` call.
fn handle_pyerr(
    py: Python<'_>,
    err: PyErr,
    description: &std::sync::Arc<str>,
    start: usize,
) -> ParseError {
    if is_parse_error(py, &err) {
        return ParseError::new(description.clone(), start);
    }
    propagate_pyerr(err);
}

/// `True` if `err` is an instance of `abnf.parser.ParseError`.  Looks
/// the class up lazily (importing the module on first use).  If the
/// import fails for any reason we conservatively treat the exception
/// as non-`ParseError` so it propagates rather than silently
/// converting into a backtrackable failure.
fn is_parse_error(py: Python<'_>, err: &PyErr) -> bool {
    let module = match py.import("abnf.parser") {
        Ok(m) => m,
        Err(_) => return false,
    };
    let cls = match module.getattr("ParseError") {
        Ok(c) => c,
        Err(_) => return false,
    };
    let cls = match cls.cast_into::<PyType>() {
        Ok(c) => c,
        Err(_) => return false,
    };
    // `PyErr::matches` is fallible since pyo3 0.23 (the isinstance check
    // can itself raise).  On error, conservatively treat the exception
    // as non-`ParseError` so it propagates rather than silently becoming
    // a backtrackable failure.
    err.matches(py, &cls).unwrap_or(false)
}
