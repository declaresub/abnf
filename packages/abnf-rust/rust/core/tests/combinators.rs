//! Behavioural parity tests against `tests/test_parser.py`.
//!
//! Each test mirrors a Python counterpart so that any divergence in
//! match semantics surfaces in `cargo test` before the PyO3 layer is
//! involved.

use abnf_core::{
    Alternation, ArcParser, Concatenation, Literal, Match, OptionParser, ParseScope, Prose, Repeat,
    Repetition,
};

/// The engine indexes by code point (issue #173), so tests build their
/// source the same way the PyO3 layer does.
fn cps(s: &str) -> Vec<u32> {
    s.chars().map(u32::from).collect()
}


fn lit(value: &str) -> ArcParser {
    Literal::string(value, false).into()
}

fn lit_cs(value: &str) -> ArcParser {
    Literal::string(value, true).into()
}

fn match_value(m: &Match, src: &[u32]) -> String {
    m.value(src)
}

#[test]
fn literal_matches_exact_case_insensitive_default() {
    let parser = Literal::string("a", false);
    let src = cps("a");
    let matches = parser.lparse(&src, 0).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].start, 1);
    assert_eq!(match_value(&matches[0], &src), "a");
}

#[test]
fn literal_case_insensitive_matches_uppercase() {
    let parser = Literal::string("abc", false);
    let src = cps("ABC");
    let matches = parser.lparse(&src, 0).unwrap();
    assert_eq!(match_value(&matches[0], &src), "ABC");
    assert_eq!(matches[0].start, 3);
}

#[test]
fn literal_case_sensitive_rejects_wrong_case() {
    let parser = Literal::string("abc", true);
    assert!(parser.lparse(&cps("ABC"), 0).is_err());
}

#[test]
fn literal_range_matches_char_in_range() {
    let parser = Literal::range(0x61, 0x7A);
    let src = cps("m");
    let matches = parser.lparse(&src, 0).unwrap();
    assert_eq!(match_value(&matches[0], &src), "m");
    assert_eq!(matches[0].start, 1);
}

#[test]
fn literal_range_rejects_char_out_of_range() {
    let parser = Literal::range(0x61, 0x7A);
    assert!(parser.lparse(&cps("0"), 0).is_err());
}

#[test]
fn literal_fails_past_source_end() {
    let parser = Literal::string("a", false);
    assert!(parser.lparse(&cps(""), 0).is_err());
    assert!(parser.lparse(&cps("a"), 1).is_err());
}

#[test]
fn prose_always_fails() {
    let parser = Prose;
    assert!(parser.lparse(&cps("a"), 0).is_err());
}

#[test]
fn alternation_default_collects_all_matches_longest_first_after_rule_sort() {
    // Without first_match, both "a" and "ab" should match "ab".
    let parser = Alternation::new(vec![lit("a"), lit("ab")]);
    let src = cps("ab");
    let matches = parser.lparse(&src, 0).unwrap();
    assert_eq!(matches.len(), 2);
}

#[test]
fn alternation_first_match_returns_after_first_success() {
    // Mirrors Python test_alternation_first_match.
    let parser = Alternation::with_first_match(vec![lit("a"), lit("ab")], true);
    let src = cps("ab");
    let matches = parser.lparse(&src, 0).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(match_value(&matches[0], &src), "a");
    assert_eq!(matches[0].start, 1);
}

#[test]
fn alternation_fail_when_no_alternative_matches() {
    let parser = Alternation::new(vec![lit("a"), lit("b")]);
    assert!(parser.lparse(&cps("c"), 0).is_err());
}

#[test]
fn concatenation_sequences_parsers() {
    let parser = Concatenation::new(vec![lit("a"), lit("b")]);
    let src = cps("ab");
    let matches = parser.lparse(&src, 0).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(match_value(&matches[0], &src), "ab");
    assert_eq!(matches[0].start, 2);
}

#[test]
fn concatenation_fails_when_any_parser_fails() {
    let parser = Concatenation::new(vec![lit("a"), lit("b")]);
    assert!(parser.lparse(&cps("ac"), 0).is_err());
}

#[test]
fn repetition_zero_or_more_yields_empty_match_when_no_repeats() {
    let parser = Repetition::new(Repeat::new(0, None), lit("a"));
    let src = cps("");
    let matches = parser.lparse(&src, 0).unwrap();
    // Empty match at start is one of the results.
    assert!(matches.iter().any(|m| m.start == 0));
}

#[test]
fn repetition_zero_or_more_collects_all_repeats() {
    let parser = Repetition::new(Repeat::new(0, None), lit("a"));
    let src = cps("aaa");
    let matches = parser.lparse(&src, 0).unwrap();
    // Longest-first, so first match should consume the full source.
    assert_eq!(matches[0].start, 3);
    assert_eq!(match_value(&matches[0], &src), "aaa");
}

#[test]
fn repetition_min_required() {
    let parser = Repetition::new(Repeat::new(2, None), lit("a"));
    assert!(parser.lparse(&cps("a"), 0).is_err());
    let src = cps("aaa");
    let matches = parser.lparse(&src, 0).unwrap();
    assert_eq!(matches[0].start, 3);
}

#[test]
fn repetition_max_bounded() {
    let parser = Repetition::new(Repeat::new(0, Some(2)), lit("a"));
    let src = cps("aaaa");
    let matches = parser.lparse(&src, 0).unwrap();
    // Cannot consume more than 2 occurrences; longest match end is 2.
    assert_eq!(matches[0].start, 2);
}

#[test]
fn option_zero_or_one_match() {
    let parser = OptionParser::new(lit("a"));
    let src = cps("a");
    let matches = parser.lparse(&src, 0).unwrap();
    assert!(matches.iter().any(|m| m.start == 1));
    assert!(matches.iter().any(|m| m.start == 0));
}

#[test]
fn backtracking_through_repetition_then_literal() {
    // Mirrors Python test_backtracking:
    // Concatenation(Repetition(0..*, Alternation(a|b)), Literal("b"))
    // on input "aababb" should succeed consuming the whole string.
    let inner: ArcParser = Alternation::new(vec![lit("a"), lit("b")]).into();
    let rep: ArcParser = Repetition::new(Repeat::new(0, None), inner).into();
    let parser = Concatenation::new(vec![rep, lit("b")]);
    let src = cps("aababb");
    let matches = parser.lparse(&src, 0).unwrap();
    assert_eq!(matches[0].start, 6);
    assert_eq!(match_value(&matches[0], &src), "aababb");
}

#[test]
fn parse_cache_short_circuits_repeated_calls_within_a_parse() {
    let parser = Repetition::new(Repeat::new(0, None), lit("a"));
    {
        let _scope = ParseScope::enter();
        let src = cps("aaa");
        let _ = parser.lparse(&src, 0).unwrap();
        let src = cps("aaa");
        let _ = parser.lparse(&src, 0).unwrap();
        let cache = parser.cache().lock().unwrap();
        assert!(cache.hits > 0, "expected cache hit on second lparse");
    }
}

#[test]
fn parse_cache_does_not_short_circuit_across_parses() {
    // The point of scoping: a second parse must not answer from the
    // first one's entries, whatever the source happens to be.
    let parser = Repetition::new(Repeat::new(0, None), lit("a"));
    {
        let _scope = ParseScope::enter();
        let src = cps("aaa");
        let _ = parser.lparse(&src, 0).unwrap();
    }
    {
        let _scope = ParseScope::enter();
        let src = cps("aaa");
        let _ = parser.lparse(&src, 0).unwrap();
        let cache = parser.cache().lock().unwrap();
        assert_eq!(cache.hits, 0, "entries leaked from the previous parse");
    }
}

#[test]
fn case_sensitive_literal_is_not_used_for_lookup() {
    // Sanity check that lit_cs constructs a case-sensitive parser.
    let parser = lit_cs("ABC");
    assert!(parser.lparse(&cps("abc"), 0).is_err());
    assert!(parser.lparse(&cps("ABC"), 0).is_ok());
}
