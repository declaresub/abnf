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
//!
//! ASCII fast paths are taken whenever both the pattern (and the
//! range bounds) are pure ASCII; that covers essentially every
//! real-world ABNF grammar and skips the UTF-8 decoder on the hot
//! match loop.

use std::sync::Arc;

use smallvec::smallvec;

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
        /// `value` is pure ASCII.  For ASCII strings,
        /// `value_chars == value.len()` and `pattern.len() ==
        /// value.len()`, which enables the byte-level fast path
        /// in `lparse`.
        is_ascii: bool,
    },
    Range {
        lo: char,
        hi: char,
        /// Both `lo` and `hi` fit in a single byte (< 128), which
        /// enables the byte-level fast path in `lparse`.
        is_ascii: bool,
    },
}

#[derive(Debug, Clone)]
pub struct Literal {
    pub kind: LiteralKind,
    pub case_sensitive: bool,
    /// Pre-formatted error description, computed once at
    /// construction and cloned cheaply (Arc bump) on every failed
    /// match.  Eliminates the per-error `format!` allocation that
    /// would otherwise show up on every backtracking branch in
    /// `Alternation` / `Concatenation`.
    error_label: Arc<str>,
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
        let is_ascii = value.is_ascii() && pattern.is_ascii();
        let suffix = if case_sensitive {
            ", case_sensitive"
        } else {
            ""
        };
        let error_label: Arc<str> =
            format!("Literal('{value}'{suffix})").into();
        Self {
            kind: LiteralKind::String {
                value,
                pattern,
                value_chars,
                is_ascii,
            },
            case_sensitive,
            error_label,
        }
    }

    pub fn range(lo: char, hi: char) -> Self {
        let error_label: Arc<str> = format!("Literal(('{lo}', '{hi}'))").into();
        let is_ascii = (lo as u32) < 128 && (hi as u32) < 128;
        Self {
            kind: LiteralKind::Range { lo, hi, is_ascii },
            case_sensitive: true,
            error_label,
        }
    }

    #[inline]
    fn parse_error(&self, start: usize) -> ParseError {
        ParseError::new(self.error_label.clone(), start)
    }

    pub fn lparse(&self, source: &str, start: usize) -> ParseResult {
        match &self.kind {
            LiteralKind::Range { lo, hi, is_ascii } => {
                if *is_ascii {
                    // Fast path: single-byte range check, no UTF-8
                    // decode.  Falls back to a char read only when
                    // the source byte at `start` is non-ASCII.
                    let bytes = source.as_bytes();
                    if start >= bytes.len() {
                        return Err(self.parse_error(start));
                    }
                    let b = bytes[start];
                    let lo_b = *lo as u8;
                    let hi_b = *hi as u8;
                    if b < 128 && b >= lo_b && b <= hi_b {
                        let matched: Arc<str> =
                            std::str::from_utf8(&bytes[start..=start])
                                .map_err(|_| self.parse_error(start))?
                                .into();
                        let node = NodeKind::Literal(LiteralNode::new(
                            matched, start, 1,
                        ));
                        return Ok(smallvec![Match::new(
                            smallvec![node],
                            start + 1
                        )]);
                    }
                    return Err(self.parse_error(start));
                }
                // Slow path: full char decoding.
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
                    Ok(smallvec![Match::new(smallvec![node], start + len)])
                } else {
                    Err(self.parse_error(start))
                }
            }
            LiteralKind::String {
                value,
                pattern,
                value_chars,
                is_ascii,
            } => {
                if *is_ascii {
                    // Fast path: byte-level comparison.  Pattern
                    // and value are both ASCII, so
                    // `value_chars == pattern.len()` and we can
                    // slice the source by byte.  Non-ASCII bytes in
                    // the source fail the byte compare naturally
                    // (a UTF-8 continuation byte is >= 0x80 while
                    // every pattern byte is < 0x80).
                    let source_bytes = source.as_bytes();
                    let pattern_bytes = pattern.as_bytes();
                    let plen = pattern_bytes.len();
                    if start + plen > source_bytes.len() {
                        return Err(self.parse_error(start));
                    }
                    let candidate = &source_bytes[start..start + plen];
                    let matches = if self.case_sensitive {
                        candidate == pattern_bytes
                    } else {
                        candidate
                            .iter()
                            .zip(pattern_bytes.iter())
                            .all(|(c, p)| c.eq_ignore_ascii_case(p))
                    };
                    if matches {
                        // SAFETY: a successful byte-level match
                        // against an ASCII pattern implies every
                        // candidate byte is < 0x80 (otherwise the
                        // case-insensitive compare would have
                        // failed), so the slice is valid UTF-8.
                        let s = unsafe {
                            std::str::from_utf8_unchecked(candidate)
                        };
                        let matched: Arc<str> = Arc::from(s);
                        let node = NodeKind::Literal(LiteralNode::new(
                            matched, start, plen,
                        ));
                        return Ok(smallvec![Match::new(
                            smallvec![node],
                            start + plen
                        )]);
                    }
                    return Err(self.parse_error(start));
                }
                // Slow path: char-based for non-ASCII values.
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
                    Ok(smallvec![Match::new(smallvec![node], start + len)])
                } else {
                    Err(self.parse_error(start))
                }
            }
        }
    }
}
