//! `OptionParser` — ABNF `[ ... ]` operator.
//!
//! Mirrors `abnf.parser.Option` (`_parser_python.py:267-288`):
//! syntactic sugar over `Repetition(Repeat(0, 1), alternation)`.

use std::sync::Arc;

use crate::parser::{ArcParser, ParseResult, ParserOp};
use crate::repetition::{Repeat, Repetition};

#[derive(Debug)]
pub struct OptionParser {
    pub alternation: ArcParser,
    repetition: Arc<Repetition>,
}

impl OptionParser {
    pub fn new(alternation: ArcParser) -> Self {
        let repetition = Arc::new(Repetition::new(Repeat::new(0, Some(1)), alternation.clone()));
        Self { alternation, repetition }
    }
}

impl ParserOp for OptionParser {
    fn lparse(&self, source: &str, start: usize) -> ParseResult {
        self.repetition.lparse(source, start)
    }
}
