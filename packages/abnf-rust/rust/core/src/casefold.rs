//! Unicode case-folding helpers.
//!
//! Matches Python's `str.casefold()` semantics via the `caseless`
//! crate.  An ASCII fast-path avoids allocation for the overwhelmingly
//! common case where neither the pattern nor the candidate contains a
//! non-ASCII code point.

use caseless::Caseless;

/// Returns `s.casefold()` as a new `String`.  ASCII-only input takes a
/// fast path that just lowercases ASCII bytes.
pub fn casefold(s: &str) -> String {
    if s.is_ascii() {
        s.to_ascii_lowercase()
    } else {
        s.chars().default_case_fold().collect()
    }
}

/// Returns `true` iff `a` and `b` are equal after case-folding.  Avoids
/// allocating intermediate `String`s when both inputs are ASCII.
#[allow(dead_code)]
pub fn casefold_eq(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        a.eq_ignore_ascii_case(b)
    } else {
        a.chars().default_case_fold().eq(b.chars().default_case_fold())
    }
}
