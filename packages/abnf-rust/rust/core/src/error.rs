//! Parse error type.
//!
//! Mirrors `abnf.parser.ParseError`: carries the byte offset at which
//! the parser that raised the error was invoked.  The "which parser
//! failed" string is captured as a description for diagnostics; the
//! Python side reconstructs the parser identity from the call stack.

use std::fmt;

#[derive(Debug, Clone)]
pub struct ParseError {
    /// Byte offset at which the failing parser was invoked.
    pub start: usize,
    /// Short description of the failing parser, e.g. `"Literal('foo')"`.
    pub parser: String,
}

impl ParseError {
    pub fn new(parser: impl Into<String>, start: usize) -> Self {
        Self { start, parser: parser.into() }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.parser, self.start)
    }
}

impl std::error::Error for ParseError {}
