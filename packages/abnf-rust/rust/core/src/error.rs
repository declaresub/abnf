//! Parse error type.
//!
//! Mirrors `abnf.parser.ParseError`: carries the byte offset at
//! which the failing parser was invoked, plus a description of
//! which parser failed.
//!
//! The description can be a static string (the combinator kind:
//! `"Alternation"`, `"Concatenation"`, ...) or a shared
//! `Arc<str>` for dynamic descriptions (rule names, literal
//! values).  Constructing a `ParseError` allocates nothing in the
//! common case where the description is a `&'static str` — important
//! because errors are constructed at every backtrack inside
//! `Alternation` and discarded immediately, and that hot allocation
//! used to dominate parse cost on ambiguous grammars.

use std::fmt;
use std::sync::Arc;

/// Description of the parser that produced a `ParseError`.
#[derive(Debug, Clone)]
pub enum ErrorParser {
    Static(&'static str),
    Shared(Arc<str>),
}

impl ErrorParser {
    pub fn as_str(&self) -> &str {
        match self {
            ErrorParser::Static(s) => s,
            ErrorParser::Shared(s) => s,
        }
    }
}

impl fmt::Display for ErrorParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&'static str> for ErrorParser {
    fn from(s: &'static str) -> Self {
        ErrorParser::Static(s)
    }
}

impl From<Arc<str>> for ErrorParser {
    fn from(s: Arc<str>) -> Self {
        ErrorParser::Shared(s)
    }
}

#[derive(Debug, Clone)]
pub struct ParseError {
    /// Byte offset at which the failing parser was invoked.
    pub start: usize,
    /// Short description of the failing parser, e.g. `"Literal('foo')"`.
    pub parser: ErrorParser,
}

impl ParseError {
    pub fn new(parser: impl Into<ErrorParser>, start: usize) -> Self {
        Self {
            start,
            parser: parser.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.parser, self.start)
    }
}

impl std::error::Error for ParseError {}
