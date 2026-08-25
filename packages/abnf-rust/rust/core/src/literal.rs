//! Terminal literal matchers.
//!
//! Two flavours:
//!
//! * `LiteralKind::String` — match a fixed sequence of code points,
//!   case-sensitive or case-insensitive (Python `Literal('foo')` /
//!   `Literal('foo', case_sensitive=True)`).
//! * `LiteralKind::Range` — match a single code point within an
//!   inclusive range (Python `Literal(('a', 'z'))`).
//!
//! Mirrors `abnf.parser.Literal._lparse_value` /
//! `_lparse_range` (`src/abnf/_parser_python.py:563-590`).
//!
//! Both the source and the pattern are code-point slices, so matching
//! is a flat index-and-compare: no UTF-8 decoding, no char boundaries,
//! and no separate ASCII fast path to keep in step with a slow one.
//! Range bounds are `u32` rather than `char` so a grammar can name a
//! surrogate, which `char` cannot represent (issue #173).

use std::sync::Arc;

use smallvec::smallvec;

use crate::casefold::ascii_fold_cp;
use crate::error::ParseError;
use crate::matcher::Match;
use crate::node::{LiteralNode, NodeKind};
use crate::parser::{ParseResult, Src};

#[derive(Debug, Clone)]
pub enum LiteralKind {
    String {
        /// The literal as written.
        value: Box<[u32]>,
        /// What a candidate is compared against: `value` when
        /// case-sensitive, its ASCII fold otherwise.  ASCII folding is
        /// length-preserving, so this always has the same length as
        /// `value`, and a match consumes exactly that many code
        /// points.
        pattern: Box<[u32]>,
    },
    Range {
        lo: u32,
        hi: u32,
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

/// Render code points for an error message.  Values that are not
/// Unicode scalars (surrogates) show as U+FFFD; this is display text
/// only, never a value handed back to the caller.
fn display(cps: &[u32]) -> String {
    cps.iter()
        .map(|cp| char::from_u32(*cp).unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

impl Literal {
    pub fn string(value: impl AsRef<str>, case_sensitive: bool) -> Self {
        let cps: Vec<u32> = value.as_ref().chars().map(u32::from).collect();
        Self::from_code_points(cps, case_sensitive)
    }

    pub fn from_code_points(value: Vec<u32>, case_sensitive: bool) -> Self {
        let pattern: Box<[u32]> = if case_sensitive {
            value.clone().into_boxed_slice()
        } else {
            value.iter().map(|cp| ascii_fold_cp(*cp)).collect()
        };
        let suffix = if case_sensitive {
            ", case_sensitive"
        } else {
            ""
        };
        let error_label: Arc<str> = format!("Literal('{}'{suffix})", display(&value)).into();
        Self {
            kind: LiteralKind::String {
                value: value.into_boxed_slice(),
                pattern,
            },
            case_sensitive,
            error_label,
        }
    }

    pub fn range(lo: u32, hi: u32) -> Self {
        let error_label: Arc<str> =
            format!("Literal(('{}', '{}'))", display(&[lo]), display(&[hi])).into();
        Self {
            kind: LiteralKind::Range { lo, hi },
            case_sensitive: true,
            error_label,
        }
    }

    #[inline]
    fn parse_error(&self, start: usize) -> ParseError {
        ParseError::new(self.error_label.clone(), start)
    }

    #[inline]
    fn matched(&self, start: usize, length: usize) -> ParseResult {
        let node = NodeKind::Literal(LiteralNode::new(start, length));
        Ok(smallvec![Match::new(smallvec![node], start + length)])
    }

    pub fn lparse(&self, source: Src<'_>, start: usize) -> ParseResult {
        match &self.kind {
            LiteralKind::Range { lo, hi } => {
                let cp = source.get(start).ok_or_else(|| self.parse_error(start))?;
                if cp >= lo && cp <= hi {
                    self.matched(start, 1)
                } else {
                    Err(self.parse_error(start))
                }
            }
            LiteralKind::String { value, pattern } => {
                // Enough source must remain for the whole literal.  This
                // one check covers both cases: a non-empty literal needs
                // room, and a zero-length one needs only `start <=
                // source.len()`, which is what `end > source.len()` says
                // when `plen` is 0.
                //
                // There used to be a `start >= source.len()` guard above
                // this, mirroring Python's, which also refused a
                // zero-length literal at end of input -- so `""` matched
                // everywhere except there.  See
                // https://github.com/declaresub/abnf/issues/260 .
                let plen = value.len();
                let end = start + plen;
                if end > source.len() {
                    return Err(self.parse_error(start));
                }
                let candidate = &source[start..end];
                let matches = if self.case_sensitive {
                    candidate == pattern.as_ref()
                } else {
                    candidate
                        .iter()
                        .zip(pattern.iter())
                        .all(|(c, p)| ascii_fold_cp(*c) == *p)
                };
                if matches {
                    self.matched(start, plen)
                } else {
                    Err(self.parse_error(start))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cps(s: &str) -> Vec<u32> {
        s.chars().map(u32::from).collect()
    }

    #[test]
    fn matches_case_insensitively_over_ascii_only() {
        let lit = Literal::string("abc", false);
        assert!(lit.lparse(&cps("ABC"), 0).is_ok());
        assert!(lit.lparse(&cps("abc"), 0).is_ok());
        // Non-ASCII never folds onto an ASCII pattern (X3).
        assert!(lit.lparse(&cps("\u{ff21}bc"), 0).is_err());
    }

    #[test]
    fn case_sensitive_requires_exact_code_points() {
        let lit = Literal::string("abc", true);
        assert!(lit.lparse(&cps("abc"), 0).is_ok());
        assert!(lit.lparse(&cps("ABC"), 0).is_err());
    }

    #[test]
    fn non_ascii_matches_itself() {
        let lit = Literal::string("café", false);
        assert!(lit.lparse(&cps("CAFé"), 0).is_ok());
        assert!(lit.lparse(&cps("cafe"), 0).is_err());
    }

    /// #173: a range may name surrogates, which `char` cannot hold.
    #[test]
    fn range_covers_surrogates() {
        let lit = Literal::range(0xD800, 0xDBFF);
        assert!(lit.lparse(&[0xD800], 0).is_ok());
        assert!(lit.lparse(&[0xDBFF], 0).is_ok());
        assert!(lit.lparse(&[0xDC00], 0).is_err());
        // ...and the whole code-point space is representable.
        let all = Literal::range(0, 0x10FFFF);
        assert!(all.lparse(&[0xDCE9], 0).is_ok());
        assert!(all.lparse(&[0x10FFFF], 0).is_ok());
    }

    /// A literal may itself contain a surrogate.
    #[test]
    fn string_of_surrogates_matches() {
        let lit = Literal::from_code_points(vec![0xD800, 0x61], false);
        assert!(lit.lparse(&[0xD800, 0x61], 0).is_ok());
        assert!(lit.lparse(&[0xD800, 0x62], 0).is_err());
    }

    /// #260: a zero-length literal matches the empty string wherever the
    /// source reaches, end of input included -- but not past it.
    #[test]
    fn empty_literal_matches_at_eof_but_not_beyond() {
        let lit = Literal::string("", false);
        assert!(lit.lparse(&[], 0).is_ok(), "empty source, offset 0");
        assert!(lit.lparse(&cps("x"), 0).is_ok(), "start of input");
        assert!(lit.lparse(&cps("x"), 1).is_ok(), "end of input");
        assert!(lit.lparse(&cps("x"), 2).is_err(), "past end of input");
        assert!(lit.lparse(&[], 1).is_err(), "past end of empty source");

        // A non-empty literal still needs room for all of itself.
        let lit = Literal::string("ab", false);
        assert!(lit.lparse(&cps("ab"), 0).is_ok());
        assert!(lit.lparse(&cps("a"), 0).is_err());
        assert!(lit.lparse(&cps("ab"), 2).is_err());
    }

    #[test]
    fn match_spans_are_code_point_indexed() {
        let lit = Literal::string("é", false);
        let m = lit.lparse(&cps("aé"), 1).expect("should match");
        assert_eq!(m[0].start, 2, "one code point consumed, not two bytes");
    }
}
