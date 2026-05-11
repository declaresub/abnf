//! `Prose` — placeholder for prose-val productions; always fails.
//!
//! ABNF allows `<prose>` to substitute for a parser when the grammar is
//! incomplete; any attempt to actually use it must error.  Mirrors
//! `abnf.parser.Prose`.

use crate::error::ParseError;
use crate::parser::{ParseResult, ParserOp};

#[derive(Debug, Clone, Default)]
pub struct Prose;

impl ParserOp for Prose {
    fn lparse(&self, _source: &str, start: usize) -> ParseResult {
        Err(ParseError::new("Prose", start))
    }
}
