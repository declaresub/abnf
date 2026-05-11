//! Combinator pyclasses — the Rust-backed `Alternation`,
//! `Concatenation`, `Repetition`, `Option`, `Literal`, `Prose`, and
//! `Repeat`.  Constructor signatures and observable attributes match
//! the Python originals so the dispatch shim in `abnf.parser` can
//! rebind these names transparently.

use std::sync::Arc;

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyTuple;

use abnf_core::{
    arc, Alternation, ArcParser, Concatenation, Literal, LiteralKind, OptionParser, Parser, Prose,
    Repeat, Repetition,
};

use crate::errors::parse_error_to_pyerr;

use crate::external::PyCallbackParser;
use crate::iter::{lparse_iter, LparseIter};

// ----------------------------------------------------------------
// Repeat (config object)
// ----------------------------------------------------------------

#[pyclass(name = "Repeat", module = "abnf_rust._ext")]
#[derive(Clone, Debug)]
pub struct PyRepeat {
    #[pyo3(get)]
    pub min: usize,
    #[pyo3(get)]
    pub max: Option<usize>,
}

#[pymethods]
impl PyRepeat {
    #[new]
    #[pyo3(signature = (min=0, max=None))]
    fn new(min: usize, max: Option<usize>) -> Self {
        Self { min, max }
    }

    fn __str__(&self) -> String {
        let m = self
            .max
            .map(|v| v.to_string())
            .unwrap_or_else(|| "None".to_string());
        format!("Repeat({}, {})", self.min, m)
    }
}

impl PyRepeat {
    pub fn to_core(&self) -> Repeat {
        Repeat::new(self.min, self.max)
    }
}

// ----------------------------------------------------------------
// Alternation
// ----------------------------------------------------------------

#[pyclass(name = "Alternation", module = "abnf_rust._ext")]
#[derive(Clone, Debug)]
pub struct PyAlternation {
    pub inner: ArcParser,
}

#[pymethods]
impl PyAlternation {
    #[new]
    #[pyo3(signature = (*parsers, first_match=false))]
    fn new(parsers: &Bound<'_, PyTuple>, first_match: bool) -> PyResult<Self> {
        let children = extract_parsers(parsers)?;
        let alt = Alternation::with_first_match(children, first_match);
        Ok(Self { inner: alt.into() })
    }

    fn lparse(&self, py: Python<'_>, source: &str, start: usize) -> PyResult<Py<LparseIter>> {
        lparse_iter(py, self.inner.lparse(source, start), source)
    }

    #[getter]
    fn first_match(&self) -> bool {
        if let Parser::Alternation(a) = &*self.inner {
            a.first_match()
        } else {
            false
        }
    }

    #[setter]
    fn set_first_match(&self, value: bool) {
        if let Parser::Alternation(a) = &*self.inner {
            a.set_first_match(value);
        }
    }

    fn __str__(&self) -> String {
        "Alternation(...)".to_string()
    }
}

// ----------------------------------------------------------------
// Concatenation
// ----------------------------------------------------------------

#[pyclass(name = "Concatenation", module = "abnf_rust._ext")]
#[derive(Clone, Debug)]
pub struct PyConcatenation {
    pub inner: ArcParser,
}

#[pymethods]
impl PyConcatenation {
    #[new]
    #[pyo3(signature = (*parsers))]
    fn new(parsers: &Bound<'_, PyTuple>) -> PyResult<Self> {
        let children = extract_parsers(parsers)?;
        Ok(Self {
            inner: Concatenation::new(children).into(),
        })
    }

    fn lparse(&self, py: Python<'_>, source: &str, start: usize) -> PyResult<Py<LparseIter>> {
        lparse_iter(py, self.inner.lparse(source, start), source)
    }

    fn __str__(&self) -> String {
        "Concatenation(...)".to_string()
    }
}

// ----------------------------------------------------------------
// Repetition
// ----------------------------------------------------------------

#[pyclass(name = "Repetition", module = "abnf_rust._ext")]
#[derive(Clone, Debug)]
pub struct PyRepetition {
    pub inner: ArcParser,
}

#[pymethods]
impl PyRepetition {
    #[new]
    fn new(repeat: PyRepeat, element: &Bound<'_, PyAny>) -> PyResult<Self> {
        let child = extract_parser(element)?;
        Ok(Self {
            inner: Repetition::new(repeat.to_core(), child).into(),
        })
    }

    fn lparse(&self, py: Python<'_>, source: &str, start: usize) -> PyResult<Py<LparseIter>> {
        lparse_iter(py, self.inner.lparse(source, start), source)
    }

    fn __str__(&self) -> String {
        "Repetition(...)".to_string()
    }
}

// ----------------------------------------------------------------
// Option
// ----------------------------------------------------------------

#[pyclass(name = "Option", module = "abnf_rust._ext")]
#[derive(Clone, Debug)]
pub struct PyOption {
    pub inner: ArcParser,
}

#[pymethods]
impl PyOption {
    #[new]
    fn new(alternation: &Bound<'_, PyAny>) -> PyResult<Self> {
        let child = extract_parser(alternation)?;
        Ok(Self {
            inner: OptionParser::new(child).into(),
        })
    }

    fn lparse(&self, py: Python<'_>, source: &str, start: usize) -> PyResult<Py<LparseIter>> {
        lparse_iter(py, self.inner.lparse(source, start), source)
    }

    fn __str__(&self) -> String {
        "Option(...)".to_string()
    }
}

// ----------------------------------------------------------------
// Literal
// ----------------------------------------------------------------

#[pyclass(name = "Literal", module = "abnf_rust._ext")]
#[derive(Clone, Debug)]
pub struct PyLiteral {
    pub inner: ArcParser,
    #[pyo3(get)]
    pub case_sensitive: bool,
}

#[pymethods]
impl PyLiteral {
    #[new]
    #[pyo3(signature = (value, case_sensitive=false))]
    fn new(value: &Bound<'_, PyAny>, case_sensitive: bool) -> PyResult<Self> {
        if let Ok(s) = value.extract::<String>() {
            Ok(Self {
                inner: Literal::string(s, case_sensitive).into(),
                case_sensitive,
            })
        } else if let Ok((lo, hi)) = value.extract::<(String, String)>() {
            let lo_char = lo.chars().next().ok_or_else(|| {
                PyTypeError::new_err("Literal range bounds must be single characters")
            })?;
            let hi_char = hi.chars().next().ok_or_else(|| {
                PyTypeError::new_err("Literal range bounds must be single characters")
            })?;
            Ok(Self {
                inner: Literal::range(lo_char, hi_char).into(),
                case_sensitive: true,
            })
        } else {
            Err(PyTypeError::new_err(
                "value argument must be a string or a 2-tuple of strings.",
            ))
        }
    }

    fn lparse(&self, py: Python<'_>, source: &str, start: usize) -> PyResult<Py<LparseIter>> {
        lparse_iter(py, self.inner.lparse(source, start), source)
    }

    fn __str__(&self) -> String {
        "Literal(...)".to_string()
    }

    /// Return the original value: a string for string literals, a
    /// 2-tuple of single-character strings for range literals.
    #[getter]
    fn value(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let Parser::Literal(lit) = &*self.inner else {
            return Err(PyTypeError::new_err("not a Literal"));
        };
        Ok(match &lit.kind {
            LiteralKind::String { value, .. } => {
                let s: &str = value.as_ref();
                s.into_py(py)
            }
            LiteralKind::Range { lo, hi } => {
                (lo.to_string(), hi.to_string()).into_py(py)
            }
        })
    }
}

// ----------------------------------------------------------------
// Prose
// ----------------------------------------------------------------

#[pyclass(name = "Prose", module = "abnf_rust._ext")]
#[derive(Clone, Debug)]
pub struct PyProse {
    pub inner: ArcParser,
}

#[pymethods]
impl PyProse {
    #[new]
    fn new() -> Self {
        Self {
            inner: Prose.into(),
        }
    }

    /// Prose is the one combinator the Python implementation does
    /// *not* implement as a generator: it raises synchronously on
    /// call.  Mirror that here so `with pytest.raises(ParseError):
    /// Prose().lparse(...)` works as written.
    fn lparse(&self, py: Python<'_>, source: &str, start: usize) -> PyResult<Py<LparseIter>> {
        match self.inner.lparse(source, start) {
            Ok(_) => lparse_iter(py, Ok(Vec::new()), source),
            Err(err) => Err(parse_error_to_pyerr(py, err)),
        }
    }

    fn __str__(&self) -> String {
        "Prose()".to_string()
    }
}

// ----------------------------------------------------------------
// Parser extraction
// ----------------------------------------------------------------

/// Extract an `ArcParser` from a Python value.  Recognises every
/// Rust-backed combinator pyclass directly; falls back to wrapping
/// the value as a `PyCallbackParser` for anything else (such as a
/// Python `Rule` instance) that exposes a `lparse(source, start)`
/// method.
pub fn extract_parser(obj: &Bound<'_, PyAny>) -> PyResult<ArcParser> {
    if let Ok(p) = obj.downcast::<PyAlternation>() {
        return Ok(p.borrow().inner.clone());
    }
    if let Ok(p) = obj.downcast::<PyConcatenation>() {
        return Ok(p.borrow().inner.clone());
    }
    if let Ok(p) = obj.downcast::<PyRepetition>() {
        return Ok(p.borrow().inner.clone());
    }
    if let Ok(p) = obj.downcast::<PyOption>() {
        return Ok(p.borrow().inner.clone());
    }
    if let Ok(p) = obj.downcast::<PyLiteral>() {
        return Ok(p.borrow().inner.clone());
    }
    if let Ok(p) = obj.downcast::<PyProse>() {
        return Ok(p.borrow().inner.clone());
    }
    // If the value is a Python Rule (or anything else carrying a
    // `name`+`lparse` shape that fits the parser-by-name contract),
    // look up — or lazily create — its shadow Rust `NamedRule` in
    // the bridge registry.  This is the fast path that keeps rule
    // references purely in Rust at parse time, instead of dispatching
    // every reference through Python.
    if obj.hasattr("name")? && obj.hasattr("lparse")? {
        let handle = crate::bridge::get_or_create(obj)?;
        return Ok(arc(handle));
    }
    // Last-resort fallback: any other object with an `lparse` method
    // is wrapped as a `PyCallbackParser`.  Reserved for callers that
    // pass duck-typed parsers without a `name` attribute.
    if obj.hasattr("lparse")? {
        let callback = PyCallbackParser::new(obj.clone().unbind(), "PyCallback");
        let parser: Parser = Parser::External(Arc::new(callback));
        return Ok(arc(parser));
    }
    Err(PyTypeError::new_err(format!(
        "expected a parser object, got {}",
        obj.get_type().name()?,
    )))
}

// `From<Parser> for ArcParser` is satisfied by the inherent `arc()`
// helper at the call site above; the impl already lives in
// `abnf-core`'s `parser.rs` via `From<X> for Parser` chained through
// `arc(p)` -> `Arc::new(p.into())`.

fn extract_parsers(parsers: &Bound<'_, PyTuple>) -> PyResult<Vec<ArcParser>> {
    parsers.iter().map(|p| extract_parser(&p)).collect()
}

/// Wrap an `ArcParser` as the matching Python pyclass.  Used by the
/// `bootstrap` function to install meta-grammar definitions onto the
/// Python `Rule` subclass.
pub fn wrap_arc_parser(py: Python<'_>, parser: ArcParser) -> PyResult<Py<PyAny>> {
    Ok(match &*parser {
        Parser::Alternation(_) => Py::new(py, PyAlternation { inner: parser.clone() })?.into_any(),
        Parser::Concatenation(_) => {
            Py::new(py, PyConcatenation { inner: parser.clone() })?.into_any()
        }
        Parser::Repetition(_) => Py::new(py, PyRepetition { inner: parser.clone() })?.into_any(),
        Parser::Option(_) => Py::new(py, PyOption { inner: parser.clone() })?.into_any(),
        Parser::Literal(l) => {
            let case_sensitive = l.case_sensitive;
            Py::new(
                py,
                PyLiteral {
                    inner: parser.clone(),
                    case_sensitive,
                },
            )?
            .into_any()
        }
        Parser::Prose(_) => Py::new(py, PyProse { inner: parser.clone() })?.into_any(),
        Parser::Rule(_) | Parser::External(_) => {
            // Rule and External nodes are reachable here only as leaf
            // children of a higher-level combinator that's being
            // wrapped.  We expose them as opaque PyProse-shaped
            // objects: their `lparse` still dispatches into Rust via
            // the inner ArcParser.  The Python facade never wraps a
            // bare Rule or External node — it always wraps the
            // outermost combinator of a rule's definition.
            //
            // For now, fall back to PyProse-shaped wrapper: the
            // engine will produce the right matches at parse time.
            // Future work: add a thin opaque pyclass for these.
            Py::new(py, PyProse { inner: parser.clone() })?.into_any()
        }
    })
}
