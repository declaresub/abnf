//! Python wrappers for `Node`, `LiteralNode`, `Match`.
//!
//! Mirrors the public attribute surface of the same-named Python
//! classes in `abnf._parser_python`.  Offsets and lengths need no
//! translation: the engine indexes by code point, which is what a
//! Python `str` index already is.
//!
//! Values are Python `str` objects sliced out of the caller's own
//! source rather than Rust strings built up during the walk.  A node
//! covers a contiguous span of the source, so one slice per node
//! reproduces exactly what concatenating its children would -- and it
//! is the only representation that survives a lone surrogate.
//!
//! Each pyclass caches its concatenated `value` string at
//! construction time.  Computing the value eagerly in Rust during the
//! tree walk costs roughly the same as the lazy Python walk that
//! follows, but it eliminates O(N) Python `getattr` round-trips later
//! when callers (notably `Rule.lparse`'s `set(...)` deduplication
//! step) ask for the value — collapsing the dominant per-parse cost.

use std::sync::Arc;

use pyo3::class::basic::CompareOp;
use pyo3::prelude::*;
use pyo3::types::PyString;
use pyo3::types::PyList;

use abnf_core::{LiteralNode, Match, Node, NodeKind};

use crate::source::substring;

// ----------------------------------------------------------------
// LiteralNode
// ----------------------------------------------------------------

#[pyclass(name = "LiteralNode", module = "abnf_rust._ext", from_py_object)]
#[derive(Debug)]
pub struct PyLiteralNode {
    /// The matched text, as a Python `str` sliced out of the source.
    /// Not a Rust `String`: a match may cover a lone surrogate, which
    /// no Rust text type can hold (issue #173).
    #[pyo3(get)]
    pub value: Py<PyString>,
    #[pyo3(get)]
    pub offset: usize,
    #[pyo3(get)]
    pub length: usize,
}

impl Clone for PyLiteralNode {
    /// `Py<PyString>` is refcounted, so cloning needs the GIL; pyo3
    /// only derives `Clone` for it under the `py-clone` feature, which
    /// panics if the token is unavailable.  Attaching explicitly is
    /// the supported way to say "I have a thread state here".
    fn clone(&self) -> Self {
        Python::attach(|py| Self {
            value: self.value.clone_ref(py),
            offset: self.offset,
            length: self.length,
        })
    }
}

#[pymethods]
impl PyLiteralNode {
    #[new]
    fn new(value: Py<PyString>, offset: usize, length: usize) -> Self {
        Self { value, offset, length }
    }

    #[getter]
    fn name(&self) -> &str {
        "literal"
    }

    /// Always an empty list — terminal nodes have no children.
    #[getter]
    fn children<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        PyList::empty(py)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!(
            "LiteralNode(value={}, offset={}, length={})",
            self.value.bind(py).repr()?,
            self.offset,
            self.length
        ))
    }

    fn __eq__(&self, py: Python<'_>, other: &Self) -> PyResult<bool> {
        Ok(self.offset == other.offset
            && self.length == other.length
            && self.value.bind(py).as_any().eq(other.value.bind(py).as_any())?)
    }

    fn __hash__(&self, py: Python<'_>) -> PyResult<isize> {
        // Hash on the same fields `__eq__` compares, and let Python
        // hash the text so the two agree for every string it can hold.
        let mut h = self.value.bind(py).as_any().hash()?;
        h = h.wrapping_mul(1_000_003).wrapping_add(self.offset as isize);
        h = h.wrapping_mul(1_000_003).wrapping_add(self.length as isize);
        Ok(h)
    }
}

impl PyLiteralNode {
    /// Offsets need no translation: the engine indexes by code point,
    /// which is what Python `str` indices already are.  The value is
    /// the corresponding slice of the caller's own string.
    pub fn from_rust(ln: &LiteralNode, source: &Bound<'_, PyString>) -> PyResult<Self> {
        let value = substring(source, ln.offset, ln.offset + ln.length)?;
        Ok(Self {
            value: value.unbind(),
            offset: ln.offset,
            length: ln.length,
        })
    }
}

// ----------------------------------------------------------------
// Node
// ----------------------------------------------------------------

#[pyclass(name = "Node", module = "abnf_rust._ext")]
#[derive(Debug)]
pub struct PyNode {
    #[pyo3(get)]
    pub name: String,
    /// Concatenated value of all descendant literals, computed once
    /// at construction time.  See module docstring for why this
    /// matters for performance.
    ///
    /// A node's value is always a contiguous span of the source, so
    /// this is one slice of the caller's `str` rather than a rebuilt
    /// string -- which is also what lets it hold surrogates.
    #[pyo3(get)]
    pub value: Py<PyString>,
    children: Vec<Py<PyAny>>,
}

#[pymethods]
impl PyNode {
    #[new]
    #[pyo3(signature = (name, *children))]
    fn new(py: Python<'_>, name: String, children: Vec<Py<PyAny>>) -> PyResult<Self> {
        // When constructed from Python (e.g. by the
        // `_parser_python.py` visitor wrapping a match's nodes), there
        // is no source object to slice, so concatenate the children's
        // values the way Python's own `Node.value` does.  Rare path.
        let value = PyString::new(py, "");
        let mut value = value.unbind();
        for child in &children {
            let v = child.bind(py).getattr("value")?;
            value = value.bind(py).as_any().add(v)?.cast_into::<PyString>()?.unbind();
        }
        Ok(Self { name, value, children })
    }

    #[getter]
    fn children<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        PyList::new(py, &self.children)
    }

    fn __repr__(&self) -> String {
        format!("Node({:?}, ...)", self.name)
    }

    fn __richcmp__(&self, py: Python<'_>, other: &Self, op: CompareOp) -> PyResult<bool> {
        let eq = self.name == other.name
            && self.value.bind(py).as_any().eq(other.value.bind(py).as_any())?;
        Ok(match op {
            CompareOp::Eq => eq,
            CompareOp::Ne => !eq,
            _ => return Err(pyo3::exceptions::PyTypeError::new_err(
                "Node only supports == and !=",
            )),
        })
    }
}

impl PyNode {
    /// Build a `PyNode` from a Rust `Node`.  Sole call site for the
    /// hot conversion path.
    ///
    /// The value is one slice of `source` covering the node's span,
    /// rather than a concatenation of the children's values: a node
    /// covers a contiguous run of the source, so the two are the same
    /// text.
    pub fn from_rust(py: Python<'_>, n: &Node, source: &Bound<'_, PyString>) -> PyResult<Self> {
        let mut children: Vec<Py<PyAny>> = Vec::with_capacity(n.children.len());
        for child in n.children.iter() {
            children.push(node_kind_to_py(py, child, source)?);
        }
        let value = span_value(py, n.children.iter(), source)?;
        Ok(Self {
            name: n.name.as_ref().to_string(),
            value: value.unbind(),
            children,
        })
    }
}

/// The text spanned by `nodes`: from the first descendant literal to
/// the last.  Empty when they cover no literal at all (e.g. an
/// `Option` that matched nothing).
fn span_value<'a, 'py, I>(
    py: Python<'py>,
    nodes: I,
    source: &Bound<'py, PyString>,
) -> PyResult<Bound<'py, PyString>>
where
    I: IntoIterator<Item = &'a NodeKind>,
{
    let bounds = nodes.into_iter().fold(None, |acc, n| {
        match (acc, n.span_bounds()) {
            (None, s) => s,
            (s, None) => s,
            (Some((a0, a1)), Some((b0, b1))) => Some((a0.min(b0), a1.max(b1))),
        }
    });
    match bounds {
        Some((start, end)) => substring(source, start, end),
        None => Ok(PyString::new(py, "")),
    }
}

/// Convert a `NodeKind` to a Python object.
fn node_kind_to_py(
    py: Python<'_>,
    kind: &NodeKind,
    source: &Bound<'_, PyString>,
) -> PyResult<Py<PyAny>> {
    Ok(match kind {
        NodeKind::Internal(n) => Py::new(py, PyNode::from_rust(py, n, source)?)?.into_any(),
        NodeKind::Literal(l) => Py::new(py, PyLiteralNode::from_rust(l, source)?)?.into_any(),
    })
}


// ----------------------------------------------------------------
// Match
// ----------------------------------------------------------------

#[pyclass(name = "Match", module = "abnf_rust._ext")]
#[derive(Debug)]
pub struct PyMatch {
    /// Match nodes as Python objects.
    pub nodes: Vec<Py<PyAny>>,
    /// Match end position, a code-point offset (Python `str` index
    /// semantics).  No translation happens any more: the engine
    /// indexes by code point too.
    #[pyo3(get)]
    pub start: usize,
    /// Cached concatenated value across all nodes, populated at
    /// construction time so `__hash__` (called per insert into
    /// `set(...)` dedup) is O(1) instead of walking the entire
    /// parse tree on every call.
    cached_value: Py<PyString>,
}

#[pymethods]
impl PyMatch {
    #[new]
    fn new(py: Python<'_>, nodes: Vec<Py<PyAny>>, start: usize) -> PyResult<Self> {
        // Constructed from Python, so there is no source to slice:
        // concatenate the nodes' values as Python does.
        let mut cached_value = PyString::new(py, "").unbind();
        for node in &nodes {
            let v = node.bind(py).getattr("value")?;
            cached_value = cached_value
                .bind(py)
                .as_any()
                .add(v)?
                .cast_into::<PyString>()?
                .unbind();
        }
        Ok(Self { nodes, start, cached_value })
    }

    #[getter]
    fn nodes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        PyList::new(py, &self.nodes)
    }

    fn __hash__(&self, py: Python<'_>) -> PyResult<isize> {
        let h = self.cached_value.bind(py).as_any().hash()?;
        Ok(h.wrapping_mul(1_000_003).wrapping_add(self.start as isize))
    }

    fn __eq__(&self, py: Python<'_>, other: &Self) -> PyResult<bool> {
        Ok(self.start == other.start
            && self.cached_value.bind(py).as_any().eq(other.cached_value.bind(py).as_any())?)
    }

    fn __str__(&self, py: Python<'_>) -> String {
        format!("Match(value={}, start={})", self.cached_value.bind(py), self.start)
    }
}

impl PyMatch {
    pub fn from_rust(py: Python<'_>, m: &Match, source: &Bound<'_, PyString>) -> PyResult<Self> {
        let mut nodes = Vec::with_capacity(m.nodes.len());
        for nk in &m.nodes {
            nodes.push(node_kind_to_py(py, nk, source)?);
        }
        let cached_value = span_value(py, m.nodes.iter(), source)?;
        Ok(Self {
            nodes,
            start: m.start,
            cached_value: cached_value.unbind(),
        })
    }
}

/// Convert a Python `Match`-like object back into a Rust `Match`.
///
/// Both sides count in code points now, so offsets pass straight
/// through.
pub fn py_match_to_rust(py_match: &Bound<'_, PyAny>) -> PyResult<Match> {
    use abnf_core::NodeList;
    use smallvec::SmallVec;
    let start: usize = py_match.getattr("start")?.extract()?;
    let nodes_py = py_match.getattr("nodes")?;
    let mut nodes: NodeList = SmallVec::new();
    for item in nodes_py.try_iter()? {
        let item = item?;
        nodes.push(py_to_node_kind(&item)?);
    }
    Ok(Match::new(nodes, start))
}

fn py_to_node_kind(obj: &Bound<'_, PyAny>) -> PyResult<NodeKind> {
    // Distinguish terminal vs internal by Python type, not by the
    // `name` attribute: ABNF rule names like `literal` in RFC 9051
    // collide with the conventional `"literal"` node-name terminal
    // nodes use, so a string-based check would misclassify rule
    // wrappers as terminals.
    //
    // A terminal contributes only its span; the text itself is read
    // back out of the source when the tree is rebuilt for Python.
    if let Ok(lit) = obj.cast::<PyLiteralNode>() {
        let lit = lit.borrow();
        return Ok(NodeKind::Literal(LiteralNode::new(lit.offset, lit.length)));
    }
    if let (Ok(offset_obj), Ok(length_obj)) = (obj.getattr("offset"), obj.getattr("length")) {
        if let (Ok(offset), Ok(length)) = (
            offset_obj.extract::<usize>(),
            length_obj.extract::<usize>(),
        ) {
            let name: String = obj
                .getattr("name")
                .and_then(|n| n.extract())
                .unwrap_or_else(|_| "literal".to_string());
            if name == "literal" {
                return Ok(NodeKind::Literal(LiteralNode::new(offset, length)));
            }
        }
    }
    let name: String = obj.getattr("name")?.extract()?;
    let children_py = obj.getattr("children")?;
    let mut children: Vec<NodeKind> = Vec::new();
    for item in children_py.try_iter()? {
        let item = item?;
        children.push(py_to_node_kind(&item)?);
    }
    Ok(NodeKind::Internal(Node::new(Arc::from(name), children)))
}
