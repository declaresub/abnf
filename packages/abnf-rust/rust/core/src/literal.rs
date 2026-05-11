//! Terminal literal matchers.
//!
//! Two flavours:
//!
//! * `LiteralKind::String` — match a fixed string, case-sensitive or
//!   case-insensitive (Python `Literal('foo')` /
//!   `Literal('foo', case_sensitive=True)`).
//! * `LiteralKind::Range` — match a single character within an
//!   inclusive code-point range (Python `Literal(('a', 'z'))`).
//!
//! Mirrors `abnf.parser.Literal._lparse_value` /
//! `_lparse_range` (`src/abnf/_parser_python.py:326-353`).

use std::sync::Arc;

use crate::casefold::casefold;
use crate::error::ParseError;
use crate::matcher::Match;
use crate::node::{LiteralNode, NodeKind};
use crate::parser::ParseResult;

#[derive(Debug, Clone)]
pub enum LiteralKind {
    String {
        value: Arc<str>,
        pattern: Arc<str>,
        value_chars: usize,
    },
    Range {
        lo: char,
        hi: char,
    },
}

#[derive(Debug, Clone)]
pub struct Literal {
    pub kind: LiteralKind,
    pub case_sensitive: bool,
}

impl Literal {
    pub fn string(value: impl Into<Arc<str>>, case_sensitive: bool) -> Self {
        let value: Arc<str> = value.into();
        let pattern: Arc<str> = if case_sensitive {
            value.clone()
        } else {
            casefold(&value).into()
        };
        let value_chars = value.chars().count();
        Self {
            kind: LiteralKind::String {
                value,
                pattern,
                value_chars,
            },
            case_sensitive,
        }
    }

    pub fn range(lo: char, hi: char) -> Self {
        Self {
            kind: LiteralKind::Range { lo, hi },
            case_sensitive: true,
        }
    }

    fn parse_error(&self, start: usize) -> ParseError {
        ParseError::new(self.describe(), start)
    }

    fn describe(&self) -> String {
        match &self.kind {
            LiteralKind::String { value, .. } => {
                let suffix = if self.case_sensitive {
                    ", case_sensitive"
                } else {
                    ""
                };
                format!("Literal('{value}'{suffix})")
            }
            LiteralKind::Range { lo, hi } => format!("Literal(('{lo}', '{hi}'))"),
        }
    }

    pub fn lparse(&self, source: &str, start: usize) -> ParseResult {
        match &self.kind {
            LiteralKind::Range { lo, hi } => {
                let remaining = source
                    .get(start..)
                    .ok_or_else(|| self.parse_error(start))?;
                let ch = remaining
                    .chars()
                    .next()
                    .ok_or_else(|| self.parse_error(start))?;
                if ch >= *lo && ch <= *hi {
                    let len = ch.len_utf8();
                    let matched: Arc<str> = ch.to_string().into();
                    let node = NodeKind::Literal(LiteralNode::new(matched, start, len));
                    Ok(vec![Match::new(vec![node], start + len)])
                } else {
                    Err(self.parse_error(start))
                }
            }
            LiteralKind::String {
                value,
                pattern,
                value_chars,
            } => {
                let remaining = source
                    .get(start..)
                    .ok_or_else(|| self.parse_error(start))?;
                let mut byte_end = 0usize;
                let mut taken = 0usize;
                for (i, ch) in remaining.char_indices() {
                    if taken == *value_chars {
                        byte_end = i;
                        break;
                    }
                    taken += 1;
                    byte_end = i + ch.len_utf8();
                }
                if taken < *value_chars {
                    return Err(self.parse_error(start));
                }
                let candidate = &remaining[..byte_end];
                let matches = if self.case_sensitive {
                    candidate == value.as_ref()
                } else {
                    casefold(candidate) == pattern.as_ref()
                };
                if matches {
                    let matched: Arc<str> = Arc::from(candidate);
                    let len = byte_end;
                    let node = NodeKind::Literal(LiteralNode::new(matched, start, len));
                    Ok(vec![Match::new(vec![node], start + len)])
                } else {
                    Err(self.parse_error(start))
                }
            }
        }
    }
}
