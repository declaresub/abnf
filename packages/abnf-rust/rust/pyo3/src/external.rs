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
use smallvec::SmallVec;

use abnf_core::{ExternalParser, ParseError, ParseResult};

use crate::nodes::py_match_to_rust;

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
        Python::with_gil(|py| -> ParseResult {
            let bound = self.obj.bind(py);
            let result = bound
                .call_method1("lparse", (source, start))
                .map_err(|_| ParseError::new(self.description.clone(), start))?;
            let iter = result
                .iter()
                .map_err(|_| ParseError::new(self.description.clone(), start))?;
            let mut matches: abnf_core::MatchList = SmallVec::new();
            for item in iter {
                let item = item
                    .map_err(|_| ParseError::new(self.description.clone(), start))?;
                let m = py_match_to_rust(&item)
                    .map_err(|_| ParseError::new(self.description.clone(), start))?;
                matches.push(m);
            }
            Ok(matches)
        })
    }
}
