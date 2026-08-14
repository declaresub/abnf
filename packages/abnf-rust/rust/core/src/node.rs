//! Parse-tree node types.
//!
//! `Node` wraps an internal (rule) match with named children; `LiteralNode`
//! captures a terminal match as a span of the source.
//!
//! Neither node stores the matched text.  A node's value is always a
//! contiguous span of the source -- verified over 2.6 million nodes
//! across the test corpus -- so the text can be recovered by slicing,
//! and the PyO3 layer does exactly that with `PyUnicode_Substring` on
//! the caller's own `str`.  Storing it here would mean choosing a Rust
//! text type, and no Rust text type can hold a lone surrogate, which
//! is a code point the grammar may legitimately name (issue #173).
//! `NodeKind` is the sum type stored in `Vec<NodeKind>` everywhere a
//! parse-tree child is needed.

use std::sync::Arc;

use crate::parser::Src;

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
    ///
    /// For grammar text, which is what the in-crate callers pass.
    /// Surrogates render as U+FFFD; the PyO3 layer never comes this
    /// way, so no user-visible value is lossy.
    pub fn value(&self, src: Src<'_>) -> String {
        let mut out = String::new();
        for child in self.children.iter() {
            child.append_value(src, &mut out);
        }
        out
    }
}

/// Terminal parse-tree node — a single literal/range match.
#[derive(Debug, Clone)]
pub struct LiteralNode {
    /// Code-point offset into the source.
    pub offset: usize,
    /// Code-point length of the matched span.
    pub length: usize,
}

impl LiteralNode {
    pub fn new(offset: usize, length: usize) -> Self {
        Self { offset, length }
    }

    /// The matched span of `src`.
    pub fn span<'a>(&self, src: Src<'a>) -> &'a [u32] {
        &src[self.offset..self.offset + self.length]
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
    pub fn append_value(&self, src: Src<'_>, out: &mut String) {
        match self {
            NodeKind::Internal(n) => {
                for c in n.children.iter() {
                    c.append_value(src, out);
                }
            }
            NodeKind::Literal(l) => {
                out.extend(
                    l.span(src)
                        .iter()
                        .map(|cp| char::from_u32(*cp).unwrap_or(char::REPLACEMENT_CHARACTER)),
                );
            }
        }
    }

    /// Materialise this node's textual value as a `String`.
    pub fn value(&self, src: Src<'_>) -> String {
        let mut s = String::new();
        self.append_value(src, &mut s);
        s
    }

    /// Code-point span covered by this node: `(offset, end)` over its
    /// descendant literals, or `None` when it covers no literal.
    pub fn span_bounds(&self) -> Option<(usize, usize)> {
        match self {
            NodeKind::Literal(l) => Some((l.offset, l.offset + l.length)),
            NodeKind::Internal(n) => n.children.iter().fold(None, |acc, c| {
                match (acc, c.span_bounds()) {
                    (None, s) => s,
                    (s, None) => s,
                    (Some((a0, a1)), Some((b0, b1))) => Some((a0.min(b0), a1.max(b1))),
                }
            }),
        }
    }
}
