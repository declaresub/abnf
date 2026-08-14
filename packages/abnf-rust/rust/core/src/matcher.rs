//! `Match` — one element of the result enumeration produced by a
//! parser's `lparse`.
//!
//! Mirrors `abnf.parser.Match`: holds the parse-tree fragment produced
//! by the match plus the code-point offset at which the next parser
//! should resume.
//!
//! Python's `Match` is equatable and hashable by `(value, start)`.
//! There are deliberately no `PartialEq`/`Hash` impls here: a match no
//! longer carries its text -- nodes are spans of the source (see
//! `node`) -- so equality would need the source as a second operand,
//! which those traits cannot take.  Nothing in the engine compares or
//! hashes a `Match`; deduplication is by end position.  An impl that
//! quietly compared spans instead of text would be a trap for the
//! first caller who needed the Python semantics.

use crate::parser::{NodeList, Src};

#[derive(Debug, Clone)]
pub struct Match {
    /// Sequence of parse-tree nodes produced by this match.
    /// `SmallVec`-backed (see `NodeList`) to keep the typical
    /// 1–4-node cases off the heap.
    pub nodes: NodeList,
    /// Code-point offset at which the next parser should resume.
    pub start: usize,
}

impl Match {
    pub fn new(nodes: NodeList, start: usize) -> Self {
        Self { nodes, start }
    }

    /// Concatenated text of all nodes in this match, read out of
    /// `src`.
    pub fn value(&self, src: Src<'_>) -> String {
        let mut out = String::new();
        self.append_value(src, &mut out);
        out
    }

    /// Append the concatenated text of all nodes to `out` (avoids an
    /// allocation when callers want to hash or compare).
    pub fn append_value(&self, src: Src<'_>, out: &mut String) {
        for n in &self.nodes {
            n.append_value(src, out);
        }
    }
}
