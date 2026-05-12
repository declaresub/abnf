//! Parse-tree node types.
//!
//! `Node` wraps an internal (rule) match with named children; `LiteralNode`
//! captures a terminal match with its source offset and byte length.
//! `NodeKind` is the sum type stored in `Vec<NodeKind>` everywhere a
//! parse-tree child is needed.

use std::sync::Arc;

/// Internal (non-terminal) parse-tree node.
///
/// `children` is stored behind an `Arc` so cloning a `Node` (and
/// therefore cloning a `NodeKind::Internal`) is an atomic pointer
/// bump rather than a deep recursive copy of the entire sub-tree.
/// `Concatenation` and `Repetition` clone prefix node lists on
/// every extension step; with a plain `Vec<NodeKind>` those clones
/// fan out into O(tree) work per extension, which dominates on
/// ambiguous grammars (e.g. RFC 3986 URI).
#[derive(Debug, Clone)]
pub struct Node {
    pub name: Arc<str>,
    pub children: Arc<Vec<NodeKind>>,
}

impl Node {
    pub fn new(name: Arc<str>, children: Vec<NodeKind>) -> Self {
        Self {
            name,
            children: Arc::new(children),
        }
    }

    /// Concatenated text of all descendant literals.  Equivalent to
    /// Python's `Node.value` property.
    pub fn value(&self) -> String {
        let mut out = String::new();
        for child in self.children.iter() {
            child.append_value(&mut out);
        }
        out
    }
}

/// Terminal parse-tree node — a single literal/range match.
#[derive(Debug, Clone)]
pub struct LiteralNode {
    pub value: Arc<str>,
    /// Byte offset into the source.
    pub offset: usize,
    /// Byte length of the matched text (== `value.len()`).
    pub length: usize,
}

impl LiteralNode {
    pub fn new(value: Arc<str>, offset: usize, length: usize) -> Self {
        Self { value, offset, length }
    }
}

/// Sum type for parse-tree children.
#[derive(Debug, Clone)]
pub enum NodeKind {
    Internal(Node),
    Literal(LiteralNode),
}

impl NodeKind {
    /// Append this node's textual value to `out`.
    pub fn append_value(&self, out: &mut String) {
        match self {
            NodeKind::Internal(n) => {
                for c in n.children.iter() {
                    c.append_value(out);
                }
            }
            NodeKind::Literal(l) => out.push_str(&l.value),
        }
    }

    /// Materialise this node's textual value as a `String`.
    pub fn value(&self) -> String {
        let mut s = String::new();
        self.append_value(&mut s);
        s
    }
}
