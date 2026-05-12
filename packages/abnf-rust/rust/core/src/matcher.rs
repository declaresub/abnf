//! `Match` — one element of the result enumeration produced by a
//! parser's `lparse`.
//!
//! Mirrors `abnf.parser.Match`: holds the parse-tree fragment produced
//! by the match plus the byte offset at which the next parser should
//! resume.  Hashing is content-based (`(concatenated_value, start)`),
//! matching the Python implementation.

use std::hash::{Hash, Hasher};

use crate::parser::NodeList;

#[derive(Debug, Clone)]
pub struct Match {
    /// Sequence of parse-tree nodes produced by this match.
    /// `SmallVec`-backed (see `NodeList`) to keep the typical
    /// 1–4-node cases off the heap.
    pub nodes: NodeList,
    /// Byte offset at which the next parser should resume.
    pub start: usize,
}

impl Match {
    pub fn new(nodes: NodeList, start: usize) -> Self {
        Self { nodes, start }
    }

    /// Concatenated text of all nodes in this match.
    pub fn value(&self) -> String {
        let mut out = String::new();
        for n in &self.nodes {
            n.append_value(&mut out);
        }
        out
    }

    /// Append the concatenated text of all nodes to `out` (avoids an
    /// allocation when callers want to hash or compare).
    pub fn append_value(&self, out: &mut String) {
        for n in &self.nodes {
            n.append_value(out);
        }
    }
}

impl PartialEq for Match {
    fn eq(&self, other: &Self) -> bool {
        // Mirrors Python: equal iff (value, start) match.  Cheap path:
        // unequal starts can never be equal.
        if self.start != other.start {
            return false;
        }
        self.value() == other.value()
    }
}

impl Eq for Match {}

impl Hash for Match {
    fn hash<H: Hasher>(&self, h: &mut H) {
        // Python hashes (value, start) as a tuple.  We mirror this by
        // feeding the value then the start position into the hasher.
        let v = self.value();
        v.hash(h);
        self.start.hash(h);
    }
}
