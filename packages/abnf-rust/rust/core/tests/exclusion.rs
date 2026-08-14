//! `NamedRule` exclusions (issue #179).
//!
//! Mirrors `Rule.exclude_rule` in the pure-Python backend: a match is
//! dropped when its span parses *completely* as the excluded rule.
//! The engine has to apply this to nested rule references, since it
//! resolves those internally and never returns to the Python
//! `Rule.lparse` that used to be the only place exclusions lived.

use std::sync::Arc;

use abnf_core::{ArcParser, Literal, NamedRule, ParseScope, Repeat, Repetition};

/// The engine indexes by code point (issue #173), so tests build their
/// source the same way the PyO3 layer does.
fn cps(s: &str) -> Vec<u32> {
    s.chars().map(u32::from).collect()
}


/// `ident = 1*%x61-7A`
fn ident_rule() -> Arc<NamedRule> {
    let rule = Arc::new(NamedRule::new("ident"));
    let letter: ArcParser = Literal::range(0x61, 0x7A).into();
    rule.set_definition(Repetition::new(Repeat::new(1, None), letter).into());
    rule
}

/// `kw = "foo"`
fn keyword_rule() -> Arc<NamedRule> {
    let rule = Arc::new(NamedRule::new("kw"));
    rule.set_definition(Literal::string("foo", false).into());
    rule
}

fn longest(rule: &NamedRule, source: &str) -> Option<usize> {
    let _scope = ParseScope::enter();
    rule.lparse(&cps(source), 0)
        .ok()
        .and_then(|matches| matches.iter().map(|m| m.start).max())
}

/// Whether the rule matches the whole of `source` -- the `parse_all`
/// question, and the one exclusions are really about.
fn matches_all(rule: &NamedRule, source: &str) -> bool {
    longest(rule, source) == Some(source.len())
}

#[test]
fn exclusion_rejects_a_complete_match() {
    let ident = ident_rule();
    ident.set_exclude(Some(keyword_rule()));
    assert!(
        !matches_all(&ident, "foo"),
        "the excluded keyword was accepted"
    );
    // Only the full-span match is dropped.  `1*ALPHA` also matches
    // "f" and "fo", neither of which is the keyword, so those
    // survive -- exactly what the pure-Python backend yields
    // (verified: both produce ends [2, 1]).  `parse_all` still fails,
    // because the longest survivor does not reach the end.
    assert_eq!(longest(&ident, "foo"), Some(2));
}

#[test]
fn exclusion_leaves_other_input_alone() {
    let ident = ident_rule();
    ident.set_exclude(Some(keyword_rule()));
    assert!(matches_all(&ident, "bar"));
}

#[test]
fn a_partial_match_does_not_exclude() {
    // "foobar" starts with the keyword but is not the keyword; the
    // Python side runs parse_all over the matched value, so only a
    // complete match disqualifies.
    let ident = ident_rule();
    ident.set_exclude(Some(keyword_rule()));
    assert!(matches_all(&ident, "foobar"));
}

#[test]
fn exclusion_can_be_cleared_and_replaced() {
    let ident = ident_rule();
    ident.set_exclude(Some(keyword_rule()));
    assert!(!matches_all(&ident, "foo"));

    ident.set_exclude(None);
    assert!(matches_all(&ident, "foo"), "clearing had no effect");

    let other = Arc::new(NamedRule::new("other"));
    other.set_definition(Literal::string("bar", false).into());
    ident.set_exclude(Some(other));
    assert!(matches_all(&ident, "foo"));
    assert!(!matches_all(&ident, "bar"));
}

#[test]
fn a_rule_with_no_exclusion_is_unaffected() {
    let ident = ident_rule();
    assert!(matches_all(&ident, "foo"));
}
