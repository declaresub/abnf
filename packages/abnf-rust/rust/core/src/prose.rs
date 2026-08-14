//! `Prose` — placeholder for prose-val productions; always fails.

use crate::error::ParseError;
use crate::parser::{ParseResult, Src};

#[derive(Debug, Clone, Default)]
pub struct Prose;

impl Prose {
    pub fn lparse(&self, _source: Src<'_>, start: usize) -> ParseResult {
        Err(ParseError::new("Prose", start))
    }
}
