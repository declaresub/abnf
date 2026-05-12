//! `Prose` — placeholder for prose-val productions; always fails.

use crate::error::ParseError;
use crate::parser::ParseResult;

#[derive(Debug, Clone, Default)]
pub struct Prose;

impl Prose {
    pub fn lparse(&self, _source: &str, start: usize) -> ParseResult {
        Err(ParseError::new("Prose", start))
    }
}
