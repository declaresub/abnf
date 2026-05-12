//! Python wrappers for `Node`, `LiteralNode`, `Match`.
//!
//! Mirrors the public attribute surface of the same-named Python
//! classes in `abnf._parser_python`.  Offsets and lengths are
//! translated from byte units to code-point units at the boundary so
//! Python users see `offset`/`length` consistent with the pure-Python
//! implementation.
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
    /// Concatenated value of all descendant literals, computed once
    /// at construction time.  See module docstring for why this
    /// matters for performance.
    #[pyo3(get)]
    pub value: String,
    children: Vec<Py<PyAny>>,
}

#[pymethods]
impl PyNode {
    #[new]
    #[pyo3(signature = (name, *children))]
    fn new(py: Python<'_>, name: String, children: Vec<Py<PyAny>>) -> PyResult<Self> {
        // When constructed from Python (e.g. by the
        // `_parser_python.py` visitor wrapping a match's nodes), we
        // do still need to materialise the value — fall back to the
        // recursive Python walk in this rare path.
        let mut value = String::new();
        for child in &children {
            let v: String = child.bind(py).getattr("value")?.extract()?;
            value.push_str(&v);
        }
        Ok(Self { name, value, children })
    }

    #[getter]
    fn children<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        PyList::new_bound(py, &self.children)
    }

    fn __repr__(&self) -> String {
        format!("Node({:?}, ...)", self.name)
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        let eq = self.name == other.name && self.value == other.value;
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
    /// Build a `PyNode` from a Rust `Node`, computing the cached
    /// value while walking the children.  Sole call site for the
    /// hot conversion path.
    pub fn from_rust(py: Python<'_>, n: &Node, source: &str) -> PyResult<Self> {
        let mut children: Vec<Py<PyAny>> = Vec::with_capacity(n.children.len());
        let mut value = String::new();
        for child in n.children.iter() {
            let (py_child, child_value) = node_kind_to_py_with_value(py, child, source)?;
            value.push_str(&child_value);
            children.push(py_child);
        }
        Ok(Self {
            name: n.name.as_ref().to_string(),
            value,
            children,
        })
    }
}

/// Convert a `NodeKind` to a Python object, also returning the
/// node's concatenated value (cheaply computed during the walk).
fn node_kind_to_py_with_value(
    py: Python<'_>,
    kind: &NodeKind,
    source: &str,
) -> PyResult<(Py<PyAny>, String)> {
    Ok(match kind {
        NodeKind::Internal(n) => {
            let py_node = PyNode::from_rust(py, n, source)?;
            let value = py_node.value.clone();
            let obj = Py::new(py, py_node)?.into_any();
            (obj, value)
        }
        NodeKind::Literal(l) => {
            let py_lit = PyLiteralNode::from_rust(l, source);
            let value = py_lit.value.clone();
            let obj = Py::new(py, py_lit)?.into_any();
            (obj, value)
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
    /// Cached concatenated value across all nodes, populated at
    /// construction time so `__hash__` (called per insert into
    /// `set(...)` dedup) is O(1) instead of walking the entire
    /// parse tree on every call.
    cached_value: String,
}

#[pymethods]
impl PyMatch {
    #[new]
    fn new(py: Python<'_>, nodes: Vec<Py<PyAny>>, start: usize) -> PyResult<Self> {
        let mut cached_value = String::new();
        for node in &nodes {
            let v: String = node.bind(py).getattr("value")?.extract()?;
            cached_value.push_str(&v);
        }
        Ok(Self { nodes, start, cached_value })
    }

    #[getter]
    fn nodes<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        PyList::new_bound(py, &self.nodes)
    }

    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        self.cached_value.hash(&mut h);
        self.start.hash(&mut h);
        h.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.start == other.start && self.cached_value == other.cached_value
    }

    fn __str__(&self) -> String {
        format!("Match(value={}, start={})", self.cached_value, self.start)
    }
}

impl PyMatch {
    pub fn from_rust(py: Python<'_>, m: &Match, source: &str) -> PyResult<Self> {
        let mut nodes = Vec::with_capacity(m.nodes.len());
        let mut cached_value = String::new();
        for nk in &m.nodes {
            let (obj, v) = node_kind_to_py_with_value(py, nk, source)?;
            cached_value.push_str(&v);
            nodes.push(obj);
        }
        Ok(Self { nodes, start: m.start, cached_value })
    }
}

/// Convert a Python `Match`-like object back into a Rust `Match`.
pub fn py_match_to_rust(py_match: &Bound<'_, PyAny>) -> PyResult<Match> {
    use abnf_core::NodeList;
    use smallvec::SmallVec;
    let start: usize = py_match.getattr("start")?.extract()?;
    let nodes_py = py_match.getattr("nodes")?;
    let mut nodes: NodeList = SmallVec::new();
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
    let name: String = obj.getattr("name")?.extract()?;
    let children_py = obj.getattr("children")?;
    let mut children: Vec<NodeKind> = Vec::new();
    for item in children_py.iter()? {
        let item = item?;
        children.push(py_to_node_kind(&item)?);
    }
    Ok(NodeKind::Internal(Node::new(Arc::from(name), children)))
}
