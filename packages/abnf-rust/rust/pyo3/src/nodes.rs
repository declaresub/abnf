//! Python wrappers for `Node`, `LiteralNode`, `Match`.
//!
//! Mirrors the public attribute surface of the same-named Python
//! classes in `abnf._parser_python`.  Offsets and lengths are
//! translated from byte units to code-point units at the boundary so
//! Python users see `offset`/`length` consistent with the
//! pure-Python implementation.

use std::sync::Arc;

use pyo3::class::basic::CompareOp;
use pyo3::prelude::*;
use pyo3::types::PyList;

use abnf_core::{LiteralNode, Match, Node, NodeKind};

// ----------------------------------------------------------------
// LiteralNode
// ----------------------------------------------------------------

#[pyclass(name = "LiteralNode", module = "abnf_rust._ext")]
#[derive(Clone, Debug)]
pub struct PyLiteralNode {
    #[pyo3(get)]
    pub value: String,
    #[pyo3(get)]
    pub offset: usize,
    #[pyo3(get)]
    pub length: usize,
}

#[pymethods]
impl PyLiteralNode {
    #[new]
    fn new(value: String, offset: usize, length: usize) -> Self {
        Self { value, offset, length }
    }

    #[getter]
    fn name(&self) -> &str {
        "literal"
    }

    /// Always an empty list — terminal nodes have no children.
    #[getter]
    fn children<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        PyList::empty_bound(py)
    }

    fn __repr__(&self) -> String {
        format!(
            "LiteralNode(value={:?}, offset={}, length={})",
            self.value, self.offset, self.length
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.value == other.value
            && self.offset == other.offset
            && self.length == other.length
    }

    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        self.value.hash(&mut h);
        self.offset.hash(&mut h);
        self.length.hash(&mut h);
        h.finish()
    }
}

impl PyLiteralNode {
    pub fn from_rust(ln: &LiteralNode, source: &str) -> Self {
        // Convert byte offsets to code-point offsets to match Python
        // semantics.  ASCII-only source skips the count entirely.
        let (cp_offset, cp_length) = if source.is_ascii() {
            (ln.offset, ln.length)
        } else {
            let before = &source[..ln.offset];
            let matched = &source[ln.offset..ln.offset + ln.length];
            (before.chars().count(), matched.chars().count())
        };
        Self {
            value: ln.value.as_ref().to_string(),
            offset: cp_offset,
            length: cp_length,
        }
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
    /// Children as a list of `PyNode`s or `PyLiteralNode`s.
    children: Vec<Py<PyAny>>,
}

#[pymethods]
impl PyNode {
    #[new]
    #[pyo3(signature = (name, *children))]
    fn new(name: String, children: Vec<Py<PyAny>>) -> Self {
        Self { name, children }
    }

    /// Returns the textual value: concatenation of all descendant
    /// literals.
    #[getter]
    fn value(&self, py: Python<'_>) -> PyResult<String> {
        let mut out = String::new();
        for child in &self.children {
            let bound = child.bind(py);
            let v: String = bound.getattr("value")?.extract()?;
            out.push_str(&v);
        }
        Ok(out)
    }

    #[getter]
    fn children<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        PyList::new_bound(py, &self.children)
    }

    fn __repr__(&self) -> String {
        format!("Node({:?}, ...)", self.name)
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp, py: Python<'_>) -> PyResult<bool> {
        let eq = self.name == other.name
            && self.children.len() == other.children.len()
            && self.value(py)? == other.value(py)?;
        Ok(match op {
            CompareOp::Eq => eq,
            CompareOp::Ne => !eq,
            _ => return Err(pyo3::exceptions::PyTypeError::new_err("Node only supports == and !=")),
        })
    }
}

impl PyNode {
    pub fn from_rust(py: Python<'_>, n: &Node, source: &str) -> PyResult<Self> {
        let mut children: Vec<Py<PyAny>> = Vec::with_capacity(n.children.len());
        for child in &n.children {
            children.push(node_kind_to_py(py, child, source)?);
        }
        Ok(Self {
            name: n.name.as_ref().to_string(),
            children,
        })
    }
}

pub fn node_kind_to_py(py: Python<'_>, kind: &NodeKind, source: &str) -> PyResult<Py<PyAny>> {
    Ok(match kind {
        NodeKind::Internal(n) => {
            let py_node = PyNode::from_rust(py, n, source)?;
            Py::new(py, py_node)?.into_any()
        }
        NodeKind::Literal(l) => {
            let py_lit = PyLiteralNode::from_rust(l, source);
            Py::new(py, py_lit)?.into_any()
        }
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
    #[pyo3(get)]
    pub start: usize,
}

#[pymethods]
impl PyMatch {
    #[new]
    fn new(nodes: Vec<Py<PyAny>>, start: usize) -> Self {
        Self { nodes, start }
    }

    #[getter]
    fn nodes<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        PyList::new_bound(py, &self.nodes)
    }

    fn __hash__(&self, py: Python<'_>) -> PyResult<u64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        let mut concat = String::new();
        for node in &self.nodes {
            let v: String = node.bind(py).getattr("value")?.extract()?;
            concat.push_str(&v);
        }
        concat.hash(&mut h);
        self.start.hash(&mut h);
        Ok(h.finish())
    }

    fn __eq__(&self, py: Python<'_>, other: &Self) -> PyResult<bool> {
        if self.start != other.start {
            return Ok(false);
        }
        Ok(self.__hash__(py)? == other.__hash__(py)?)
    }

    fn __str__(&self, py: Python<'_>) -> PyResult<String> {
        let mut concat = String::new();
        for node in &self.nodes {
            let v: String = node.bind(py).getattr("value")?.extract()?;
            concat.push_str(&v);
        }
        Ok(format!("Match(value={concat}, start={})", self.start))
    }
}

impl PyMatch {
    pub fn from_rust(py: Python<'_>, m: &Match, source: &str) -> PyResult<Self> {
        let mut nodes = Vec::with_capacity(m.nodes.len());
        for nk in &m.nodes {
            nodes.push(node_kind_to_py(py, nk, source)?);
        }
        Ok(Self { nodes, start: m.start })
    }
}

/// Convert a `Vec<Match>` from Rust into a `Vec<Py<PyMatch>>`.
pub fn rust_matches_to_py(
    py: Python<'_>,
    matches: Vec<Match>,
    source: &str,
) -> PyResult<Vec<Py<PyMatch>>> {
    matches
        .into_iter()
        .map(|m| Py::new(py, PyMatch::from_rust(py, &m, source)?))
        .collect()
}

/// Convert a Python `Match`-like object back into a Rust `Match`.
///
/// Accepts any object exposing `.nodes` (iterable) and `.start` (int).
/// Each node must in turn expose `.name` and either `.value`+`.offset`+`.length`
/// (terminal) or `.children` (internal).  Used by `ExternalParser`
/// implementations that bridge a Python parser into Rust.
pub fn py_match_to_rust(py_match: &Bound<'_, PyAny>) -> PyResult<Match> {
    let start: usize = py_match.getattr("start")?.extract()?;
    let nodes_py = py_match.getattr("nodes")?;
    let mut nodes: Vec<NodeKind> = Vec::new();
    for item in nodes_py.iter()? {
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
    if let Ok(lit) = obj.downcast::<PyLiteralNode>() {
        let lit = lit.borrow();
        let arc: Arc<str> = Arc::from(lit.value.as_str());
        return Ok(NodeKind::Literal(LiteralNode::new(arc, lit.offset, lit.length)));
    }
    // Fallback: probe for a `length` attribute that internal `Node`
    // values do not expose; covers pure-Python `LiteralNode`
    // instances that may flow through during mixed-backend testing.
    if let (Ok(value_obj), Ok(offset_obj), Ok(length_obj)) = (
        obj.getattr("value"),
        obj.getattr("offset"),
        obj.getattr("length"),
    ) {
        if let (Ok(value), Ok(offset), Ok(length)) = (
            value_obj.extract::<String>(),
            offset_obj.extract::<usize>(),
            length_obj.extract::<usize>(),
        ) {
            let name: String = obj
                .getattr("name")
                .and_then(|n| n.extract())
                .unwrap_or_else(|_| "literal".to_string());
            if name == "literal" {
                let arc: Arc<str> = Arc::from(value);
                return Ok(NodeKind::Literal(LiteralNode::new(arc, offset, length)));
            }
        }
    }
    // Internal node: walk its children.
    let name: String = obj.getattr("name")?.extract()?;
    let children_py = obj.getattr("children")?;
    let mut children: Vec<NodeKind> = Vec::new();
    for item in children_py.iter()? {
        let item = item?;
        children.push(py_to_node_kind(&item)?);
    }
    Ok(NodeKind::Internal(Node::new(Arc::from(name), children)))
}
