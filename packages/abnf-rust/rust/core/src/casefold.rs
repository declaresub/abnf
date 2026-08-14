//! Case-folding helpers.
//!
//! Two different questions, deliberately kept apart:
//!
//! * [`ascii_fold`] folds literals, over US-ASCII only.  RFC 5234 §2.3
//!   makes literals case-insensitive and says their character set is
//!   US-ASCII, so nothing outside ASCII takes part.  It is also
//!   length-preserving, which full folding is not.
//! * [`casefold`] matches Python's `str.casefold()` via the `caseless`
//!   crate, and is used for *rule names*, where both backends have
//!   always agreed on full folding.

use caseless::Caseless;

/// Fold `s` over US-ASCII only: `A-Z` map to `a-z`, everything else is
/// left exactly as it is.  Length-preserving, so a folded candidate has
/// the same length as the source region it came from.
pub fn ascii_fold(s: &str) -> String {
    s.to_ascii_lowercase()
}

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
