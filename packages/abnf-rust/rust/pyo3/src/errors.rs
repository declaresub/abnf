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
    PyErr::from_value_bound(exc)
}

fn get_parse_error_class(py: Python<'_>) -> PyResult<Bound<'_, PyType>> {
    let module = py.import_bound("abnf.parser")?;
    let cls = module.getattr("ParseError")?;
    cls.downcast_into::<PyType>()
        .map_err(|e| e.into())
}
