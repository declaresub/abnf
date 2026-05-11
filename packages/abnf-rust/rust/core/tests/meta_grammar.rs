//! Meta-grammar parity tests.
//!
//! Builds the hard-coded ABNF meta-grammar, parses representative
//! rule and `rulelist` source strings through it, then exercises the
//! resulting combinator tree.  Asserts both that the meta-grammar
//! recognises its input and that the visitor produces a parser whose
//! behaviour matches what one would write by hand.

use std::sync::Arc;

use abnf_core::{
    build_meta_grammar, parse_rule_source, parse_rulelist_source, Literal, NamedRule, RuleRegistry,
};

fn fresh_registry() -> RuleRegistry {
    build_meta_grammar()
}

#[test]
fn meta_grammar_recognises_simple_rule() {
    let mut registry = fresh_registry();
    let rule = parse_rule_source("foo = \"bar\"\r\n", &mut registry).expect("parse");
    assert_eq!(rule.name.as_ref(), "foo");
    // Parse "bar" through the new rule.
    let matches = rule.lparse("bar", 0).unwrap();
    assert_eq!(matches[0].start, 3);
}

#[test]
fn meta_grammar_recognises_alternation_rule() {
    let mut registry = fresh_registry();
    let rule = parse_rule_source("color = \"red\" / \"green\" / \"blue\"\r\n", &mut registry)
        .expect("parse");
    let cases = [("red", 3), ("green", 5), ("blue", 4)];
    for (input, end) in cases {
        let matches = rule.lparse(input, 0).unwrap();
        assert_eq!(matches[0].start, end, "input {input}");
    }
}

#[test]
fn meta_grammar_recognises_repetition() {
    let mut registry = fresh_registry();
    let rule = parse_rule_source("digits = 1*DIGIT\r\n", &mut registry).expect("parse");
    let matches = rule.lparse("12345abc", 0).unwrap();
    assert_eq!(matches[0].start, 5);
}

#[test]
fn meta_grammar_recognises_option_and_group() {
    let mut registry = fresh_registry();
    let rule = parse_rule_source(
        "signed = [\"+\" / \"-\"] 1*DIGIT\r\n",
        &mut registry,
    )
    .expect("parse");
    let cases = [("+42", 3), ("-7", 2), ("99", 2)];
    for (input, end) in cases {
        let matches = rule.lparse(input, 0).unwrap();
        assert_eq!(matches[0].start, end, "input {input}");
    }
}

#[test]
fn meta_grammar_recognises_num_val_range() {
    let mut registry = fresh_registry();
    let rule = parse_rule_source("hex-digit = %x30-39 / %x41-46\r\n", &mut registry)
        .expect("parse");
    for input in ["0", "9", "A", "F"] {
        let matches = rule.lparse(input, 0).unwrap();
        assert_eq!(matches[0].start, 1, "input {input}");
    }
    assert!(rule.lparse("G", 0).is_err());
}

#[test]
fn meta_grammar_recognises_num_val_concat() {
    // "%d97.98.99" should match "abc" exactly.
    let mut registry = fresh_registry();
    let rule = parse_rule_source("abc = %d97.98.99\r\n", &mut registry).expect("parse");
    let matches = rule.lparse("abc", 0).unwrap();
    assert_eq!(matches[0].start, 3);
}

#[test]
fn meta_grammar_recognises_case_sensitive_string() {
    let mut registry = fresh_registry();
    let rule = parse_rule_source("strict = %s\"FOO\"\r\n", &mut registry).expect("parse");
    assert!(rule.lparse("FOO", 0).is_ok());
    assert!(rule.lparse("foo", 0).is_err());
}

#[test]
fn meta_grammar_recognises_rulelist_multi_rule() {
    let mut registry = fresh_registry();
    let source = "first = \"a\"\r\nsecond = first \"b\"\r\n";
    let rules = parse_rulelist_source(source, &mut registry).expect("rulelist");
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].name.as_ref(), "first");
    assert_eq!(rules[1].name.as_ref(), "second");
    let matches = rules[1].lparse("ab", 0).unwrap();
    assert_eq!(matches[0].start, 2);
}

#[test]
fn meta_grammar_supports_combine_operator() {
    let mut registry = fresh_registry();
    // First define `kw = "yes"`, then extend it with `=/` to also accept "no".
    parse_rule_source("kw = \"yes\"\r\n", &mut registry).expect("base");
    parse_rule_source("kw =/ \"no\"\r\n", &mut registry).expect("extend");
    let kw: Arc<NamedRule> = registry.get("kw").expect("kw");
    assert!(kw.lparse("yes", 0).is_ok());
    assert!(kw.lparse("no", 0).is_ok());
}

#[test]
fn core_rule_alpha_matches_letters() {
    let registry = fresh_registry();
    let alpha = registry.get("ALPHA").expect("ALPHA installed");
    assert!(alpha.lparse("a", 0).is_ok());
    assert!(alpha.lparse("Z", 0).is_ok());
    assert!(alpha.lparse("0", 0).is_err());
}

#[test]
fn core_rule_crlf_two_chars() {
    let registry = fresh_registry();
    let crlf = registry.get("CRLF").expect("CRLF installed");
    let matches = crlf.lparse("\r\n", 0).unwrap();
    assert_eq!(matches[0].start, 2);
}

#[test]
fn case_insensitive_string_default() {
    // Sanity: char-val produces case-insensitive literal by default.
    let lit = Literal::string("Foo", false);
    assert!(lit.lparse("FOO", 0).is_ok());
    assert!(lit.lparse("foo", 0).is_ok());
}
