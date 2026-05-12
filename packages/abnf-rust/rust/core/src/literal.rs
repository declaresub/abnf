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
                // Mirror Python's `if start < len(source)` guard
                // (see `_lparse_value` in `_parser_python.py`).  This
                // is the only path where `Literal('')` could match at
                // EOF — Python explicitly raises there even for an
                // empty literal, so we do too.  Without this check
                // the byte-level fast path's `start + plen >
                // source_bytes.len()` test would let `plen == 0`
                // through and silently match the empty string at
                // any out-of-range start.
                if start >= source.len() {
                    return Err(self.parse_error(start));
                }
                if *is_ascii {
                    // Fast path: byte-level comparison.  Pattern
                    // and value are both ASCII, so
                    // `value_chars == pattern.len()` and we can
                    // slice the source by byte.  Non-ASCII bytes in
                    // the source fail the byte compare naturally
                    // (a UTF-8 continuation byte is >= 0x80 while
                    // every pattern byte is < 0x80).
                    //
                    // Exception: in case-insensitive mode, some
                    // non-ASCII codepoints casefold to an ASCII
                    // multi-character sequence (e.g. 'ß' → 'ss',
                    // 'ﬃ' → 'ffi').  Python's `Literal('ss',
                    // case_sensitive=False)` matches a source of 'ß';
                    // the byte-level fast path would incorrectly
                    // reject it.  Fall through to the slow path
                    // whenever the candidate region contains any
                    // non-ASCII byte, where the full casefold can
                    // express the expansion.
                    let source_bytes = source.as_bytes();
                    let pattern_bytes = pattern.as_bytes();
                    let plen = pattern_bytes.len();
                    if start + plen <= source_bytes.len() {
                        let candidate = &source_bytes[start..start + plen];
                        let candidate_is_ascii =
                            candidate.iter().all(|b| *b < 128);
                        if self.case_sensitive || candidate_is_ascii {
                            return self.lparse_ascii_candidate(
                                candidate,
                                pattern_bytes,
                                start,
                            );
                        }
                        // Non-ASCII candidate in case-insensitive
                        // mode: fall through to the slow path below.
                    } else if self.case_sensitive {
                        // Case-sensitive can never extend past EOF.
                        return Err(self.parse_error(start));
                    }
                    // Case-insensitive: even if the byte-slice would
                    // run past EOF, the slow path needs to consider
                    // shorter casefold-equivalent candidates (Python's
                    // `source[start:start+N]` is permissive).
                }
                // Slow path: char-based.  Permissive about taken
                // count when case-insensitive, since casefold can
                // expand a short candidate into a pattern-length
                // sequence (e.g. 'ß' → 'ss' satisfies a 2-char pattern
                // from a 1-char source).
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
                if self.case_sensitive && taken < *value_chars {
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
                    return Ok(smallvec![Match::new(smallvec![node], start + len)]);
                }
                Err(self.parse_error(start))
            }
        }
    }

    /// ASCII-candidate fast path body.  Called from `lparse` once
    /// the pattern is known to be ASCII and the candidate region
    /// (or, for case-sensitive matching, the source bytes in that
    /// region) is also ASCII.  Byte-level comparison with explicit
    /// UTF-8 validation on success — the validation is cheap (a
    /// SIMD-scanned check over a few bytes) and avoids any
    /// `unsafe { from_utf8_unchecked }` surface area.
    fn lparse_ascii_candidate(
        &self,
        candidate: &[u8],
        pattern_bytes: &[u8],
        start: usize,
    ) -> ParseResult {
        let matches = if self.case_sensitive {
            candidate == pattern_bytes
        } else {
            candidate
                .iter()
                .zip(pattern_bytes.iter())
                .all(|(c, p)| c.eq_ignore_ascii_case(p))
        };
        if !matches {
            return Err(self.parse_error(start));
        }
        let s = std::str::from_utf8(candidate)
            .expect("ASCII pattern match implies ASCII candidate");
        let plen = pattern_bytes.len();
        let matched: Arc<str> = Arc::from(s);
        let node = NodeKind::Literal(LiteralNode::new(matched, start, plen));
        Ok(smallvec![Match::new(smallvec![node], start + plen)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H2 regression: the ASCII fast path's `from_utf8` call must
    /// remain sound for every input we throw at it.  Exercise the
    /// path with adversarial non-ASCII source bytes that could
    /// produce invalid UTF-8 slices if the safety invariant
    /// (byte-match against ASCII pattern ⇒ candidate is ASCII)
    /// were ever broken by a refactor.
    #[test]
    fn ascii_fast_path_rejects_non_ascii_source_without_panicking() {
        // Case-insensitive pattern against source bytes whose values
        // would matter if `eq_ignore_ascii_case` ever changed semantics.
        let lit = Literal::string("abc", false);
        // Source is a single non-ASCII codepoint padded with ASCII.
        let cases: &[&str] = &[
            "\u{00ff}bc",   // first byte 0xc3
            "a\u{00ff}c",   // second byte non-ASCII
            "ab\u{00ff}",   // last "byte" replaced by non-ASCII
            "\u{1f600}bc",  // 4-byte UTF-8 codepoint at start
            "ABC",          // matches case-insensitively (success path)
            "abc",          // exact match
        ];
        for src in cases {
            // Must not panic regardless of source contents.
            let result = lit.lparse(src, 0);
            match *src {
                "ABC" | "abc" => assert!(result.is_ok(), "expected match on {src:?}"),
                _ => assert!(result.is_err(), "expected ParseError on {src:?}"),
            }
        }
    }

    /// Same defence for case-sensitive ASCII fast path: non-ASCII
    /// bytes in the candidate region must be rejected cleanly.
    #[test]
    fn ascii_fast_path_case_sensitive_rejects_non_ascii() {
        let lit = Literal::string("abc", true);
        assert!(lit.lparse("abc", 0).is_ok());
        assert!(lit.lparse("ABC", 0).is_err()); // case-sensitive => no match
        assert!(lit.lparse("\u{00ff}bc", 0).is_err());
        assert!(lit.lparse("a\u{1f600}c", 0).is_err());
    }
}
