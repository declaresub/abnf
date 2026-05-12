//! Error lift helpers.
//!
//! Translates an `abnf_core::ParseError` into a `PyErr` that uses the
//! Python `ParseError` class defined in `abnf.parser`.  Doing so
//! keeps `except abnf.parser.ParseError` clauses working
//! identically whether the parser is implemented in Python or Rust.

use pyo3::prelude::*;
use pyo3::types::PyType;

use abnf_core::ParseError;

/// Look up `abnf.parser.ParseError` (importing the module if needed)
/// and return a `PyErr` instance carrying `(parser_description, start)`.
pub fn parse_error_to_pyerr(py: Python<'_>, err: ParseError) -> PyErr {
    let cls = match get_parse_error_class(py) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let exc = match cls.call1((err.parser.as_str(), err.start)) {
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
