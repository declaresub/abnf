//! Parser trait and shared type aliases.
//!
//! All combinator types implement `ParserOp`; trees of combinators are
//! built by composing `Arc<dyn ParserOp>` (`ArcParser`).  Trait-object
//! dispatch keeps the API straightforward at the cost of one vtable
//! lookup per combinator — negligible against the parsing work itself.

use std::fmt::Debug;
use std::sync::Arc;

use crate::error::ParseError;
use crate::matcher::Match;

/// Result of a single combinator's `lparse`: either the full set of
/// matches produced at this position (possibly empty matches with the
/// same `start`) or a `ParseError`.
pub type ParseResult = Result<Vec<Match>, ParseError>;

/// Trait implemented by every combinator.
///
/// `lparse` enumerates all matches at the given byte offset.  Mirrors
/// the generator-returning method of the same name on the Python side;
/// because Rust has no native generator type yet, we materialise the
/// match set into a `Vec`.  In real grammars this is one or two
/// matches per call so the allocation is cheap.
pub trait ParserOp: Debug + Send + Sync {
    fn lparse(&self, source: &str, start: usize) -> ParseResult;
}

/// Shared parser handle used to compose trees.
pub type ArcParser = Arc<dyn ParserOp>;
