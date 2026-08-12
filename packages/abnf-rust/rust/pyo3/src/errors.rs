//! Error lift helpers.
//!
//! Translates an `abnf_core::ParseError` into a `PyErr` that uses the
//! Python `ParseError` class defined in `abnf.parser`.  Doing so
//! keeps `except abnf.parser.ParseError` clauses working
//! identically whether the parser is implemented in Python or Rust.

use pyo3::prelude::*;
use pyo3::types::PyType;

use abnf_core::ParseError;

use crate::offset::byte_to_cp;

/// Look up `abnf.parser.ParseError` (importing the module if needed)
/// and return a `PyErr` instance carrying `(parser_description, start)`.
///
/// `err.start` is a UTF-8 byte offset (core convention); it is
/// translated to a code-point offset against `source` before being
/// passed to Python, so `parse_error.start` indexes the user's `str`
/// correctly on non-ASCII input.
pub fn parse_error_to_pyerr(py: Python<'_>, err: ParseError, source: &str) -> PyErr {
    let cls = match get_parse_error_class(py) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let cp_start = byte_to_cp(source, err.start);
    let exc = match cls.call1((err.parser.as_str(), cp_start)) {
        Ok(o) => o,
        Err(e) => return e,
    };
    PyErr::from_value(exc)
}

fn get_parse_error_class(py: Python<'_>) -> PyResult<Bound<'_, PyType>> {
    let module = py.import("abnf.parser")?;
    let cls = module.getattr("ParseError")?;
    cls.cast_into::<PyType>()
        .map_err(|e| e.into())
}

/// Build an `abnf.parser.GrammarError` carrying `message`.
///
/// Same reasoning as `parse_error_to_pyerr`: the Python class is the
/// one users write `except` clauses against, so a malformed grammar
/// has to raise it whichever backend caught the problem.  Only ever
/// called on an error path, so the module import costs nothing in
/// normal operation.
pub fn grammar_error(py: Python<'_>, message: &str) -> PyErr {
    let cls = match get_grammar_error_class(py) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match cls.call1((message,)) {
        Ok(exc) => PyErr::from_value(exc),
        Err(e) => e,
    }
}

fn get_grammar_error_class(py: Python<'_>) -> PyResult<Bound<'_, PyType>> {
    let module = py.import("abnf.parser")?;
    let cls = module.getattr("GrammarError")?;
    cls.cast_into::<PyType>()
        .map_err(|e| e.into())
}
