//! The ABNF meta-grammar (RFC 5234 + RFC 7405 character-string rules).
//!
//! Mirrors the bootstrap block at `_parser_python.py:776-1033`.

use crate::alternation::Alternation;
use crate::concatenation::Concatenation;
use crate::literal::Literal;
use crate::option::OptionParser;
use crate::parser::ArcParser;
use crate::registry::RuleRegistry;
use crate::repetition::{Repeat, Repetition};

fn lit_ci(value: &str) -> ArcParser {
    Literal::string(value, false).into()
}

fn rep(min: usize, max: Option<usize>, element: ArcParser) -> ArcParser {
    Repetition::new(Repeat::new(min, max), element).into()
}

fn alt(parsers: Vec<ArcParser>) -> ArcParser {
    Alternation::new(parsers).into()
}

fn concat(parsers: Vec<ArcParser>) -> ArcParser {
    Concatenation::new(parsers).into()
}

fn opt(parser: ArcParser) -> ArcParser {
    OptionParser::new(parser).into()
}

/// Populate `registry` with the 24 ABNF meta-grammar rules.  The
/// registry should already contain the RFC 5234 core rules
/// ([`crate::install_core_rules`]).
pub fn install_meta_grammar(registry: &mut RuleRegistry) {
    // Pre-create every meta-grammar rule reference up front.
    let rulename = registry.get_or_create("rulename");
    let defined_as = registry.get_or_create("defined-as");
    let elements = registry.get_or_create("elements");
    let c_wsp = registry.get_or_create("c-wsp");
    let c_nl = registry.get_or_create("c-nl");
    let comment = registry.get_or_create("comment");
    let alternation_ref = registry.get_or_create("alternation");
    let concatenation_ref = registry.get_or_create("concatenation");
    let repetition_ref = registry.get_or_create("repetition");
    let repeat_ref = registry.get_or_create("repeat");
    let element = registry.get_or_create("element");
    let group = registry.get_or_create("group");
    let option_ref = registry.get_or_create("option");
    let num_val = registry.get_or_create("num-val");
    let bin_val = registry.get_or_create("bin-val");
    let dec_val = registry.get_or_create("dec-val");
    let hex_val = registry.get_or_create("hex-val");
    let prose_val = registry.get_or_create("prose-val");
    let char_val = registry.get_or_create("char-val");
    let case_insensitive_string = registry.get_or_create("case-insensitive-string");
    let case_sensitive_string = registry.get_or_create("case-sensitive-string");
    let quoted_string = registry.get_or_create("quoted-string");
    let rule_ref = registry.get_or_create("rule");

    // Core-rule references.
    let alpha = registry.get_or_create("ALPHA");
    let digit = registry.get_or_create("DIGIT");
    let bit = registry.get_or_create("BIT");
    let hexdig = registry.get_or_create("HEXDIG");
    let wsp = registry.get_or_create("WSP");
    let vchar = registry.get_or_create("VCHAR");
    let crlf = registry.get_or_create("CRLF");
    let dquote = registry.get_or_create("DQUOTE");

    // rulelist = 1*( rule / (*c-wsp c-nl) )
    registry.define(
        "rulelist",
        rep(
            1,
            None,
            alt(vec![
                rule_ref.clone(),
                concat(vec![rep(0, None, c_wsp.clone()), c_nl.clone()]),
            ]),
        ),
    );

    // rule = rulename defined-as elements c-nl
    registry.define(
        "rule",
        concat(vec![
            rulename.clone(),
            defined_as.clone(),
            elements.clone(),
            c_nl.clone(),
        ]),
    );

    // rulename = ALPHA *(ALPHA / DIGIT / "-")
    registry.define(
        "rulename",
        concat(vec![
            alpha.clone(),
            rep(0, None, alt(vec![alpha.clone(), digit.clone(), lit_ci("-")])),
        ]),
    );

    // defined-as = *c-wsp ("=/" / "=") *c-wsp
    registry.define(
        "defined-as",
        concat(vec![
            rep(0, None, c_wsp.clone()),
            alt(vec![lit_ci("=/"), lit_ci("=")]),
            rep(0, None, c_wsp.clone()),
        ]),
    );

    // elements = alternation *c-wsp
    registry.define(
        "elements",
        concat(vec![alternation_ref.clone(), rep(0, None, c_wsp.clone())]),
    );

    // c-wsp = WSP / (c-nl WSP)
    registry.define(
        "c-wsp",
        alt(vec![wsp.clone(), concat(vec![c_nl.clone(), wsp.clone()])]),
    );

    // c-nl = comment / CRLF
    registry.define("c-nl", alt(vec![comment.clone(), crlf.clone()]));

    // comment = ";" *(WSP / VCHAR) CRLF
    registry.define(
        "comment",
        concat(vec![
            lit_ci(";"),
            rep(0, None, alt(vec![wsp.clone(), vchar.clone()])),
            crlf.clone(),
        ]),
    );

    // alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)
    registry.define(
        "alternation",
        concat(vec![
            concatenation_ref.clone(),
            rep(
                0,
                None,
                concat(vec![
                    rep(0, None, c_wsp.clone()),
                    lit_ci("/"),
                    rep(0, None, c_wsp.clone()),
                    concatenation_ref.clone(),
                ]),
            ),
        ]),
    );

    // concatenation = repetition *(1*c-wsp repetition)
    registry.define(
        "concatenation",
        concat(vec![
            repetition_ref.clone(),
            rep(
                0,
                None,
                concat(vec![rep(1, None, c_wsp.clone()), repetition_ref.clone()]),
            ),
        ]),
    );

    // repetition = [repeat] element
    registry.define(
        "repetition",
        concat(vec![opt(repeat_ref.clone()), element.clone()]),
    );

    // repeat = *DIGIT "*" *DIGIT / 1*DIGIT
    registry.define(
        "repeat",
        alt(vec![
            concat(vec![
                rep(0, None, digit.clone()),
                lit_ci("*"),
                rep(0, None, digit.clone()),
            ]),
            rep(1, None, digit.clone()),
        ]),
    );

    // element = rulename / group / option / char-val / num-val / prose-val
    registry.define(
        "element",
        alt(vec![
            rulename.clone(),
            group.clone(),
            option_ref.clone(),
            char_val.clone(),
            num_val.clone(),
            prose_val.clone(),
        ]),
    );

    // group = "(" *c-wsp alternation *c-wsp ")"
    registry.define(
        "group",
        concat(vec![
            lit_ci("("),
            rep(0, None, c_wsp.clone()),
            alternation_ref.clone(),
            rep(0, None, c_wsp.clone()),
            lit_ci(")"),
        ]),
    );

    // option = "[" *c-wsp alternation *c-wsp "]"
    registry.define(
        "option",
        concat(vec![
            lit_ci("["),
            rep(0, None, c_wsp.clone()),
            alternation_ref.clone(),
            rep(0, None, c_wsp.clone()),
            lit_ci("]"),
        ]),
    );

    // num-val = "%" (bin-val / dec-val / hex-val)
    registry.define(
        "num-val",
        concat(vec![
            lit_ci("%"),
            alt(vec![bin_val.clone(), dec_val.clone(), hex_val.clone()]),
        ]),
    );

    // bin-val = "b" 1*BIT [1*("." 1*BIT) / ("-" 1*BIT)]
    registry.define(
        "bin-val",
        concat(vec![
            lit_ci("b"),
            concat(vec![
                rep(1, None, bit.clone()),
                opt(alt(vec![
                    rep(
                        1,
                        None,
                        concat(vec![lit_ci("."), rep(1, None, bit.clone())]),
                    ),
                    concat(vec![lit_ci("-"), rep(1, None, bit.clone())]),
                ])),
            ]),
        ]),
    );

    // dec-val = "d" 1*DIGIT [1*("." 1*DIGIT) / ("-" 1*DIGIT)]
    registry.define(
        "dec-val",
        concat(vec![
            lit_ci("d"),
            concat(vec![
                rep(1, None, digit.clone()),
                opt(alt(vec![
                    rep(
                        1,
                        None,
                        concat(vec![lit_ci("."), rep(1, None, digit.clone())]),
                    ),
                    concat(vec![lit_ci("-"), rep(1, None, digit.clone())]),
                ])),
            ]),
        ]),
    );

    // hex-val = "x" 1*HEXDIG [1*("." 1*HEXDIG) / ("-" 1*HEXDIG)]
    registry.define(
        "hex-val",
        concat(vec![
            lit_ci("x"),
            concat(vec![
                rep(1, None, hexdig.clone()),
                opt(alt(vec![
                    rep(
                        1,
                        None,
                        concat(vec![lit_ci("."), rep(1, None, hexdig.clone())]),
                    ),
                    concat(vec![lit_ci("-"), rep(1, None, hexdig.clone())]),
                ])),
            ]),
        ]),
    );

    // prose-val = "<" *(%x20-3D / %x3F-7E) ">"
    registry.define(
        "prose-val",
        concat(vec![
            lit_ci("<"),
            rep(
                0,
                None,
                alt(vec![
                    Literal::range('\x20', '\x3D').into(),
                    Literal::range('\x3F', '\x7E').into(),
                ]),
            ),
            lit_ci(">"),
        ]),
    );

    // char-val = case-insensitive-string / case-sensitive-string
    registry.define(
        "char-val",
        alt(vec![
            case_insensitive_string.clone(),
            case_sensitive_string.clone(),
        ]),
    );

    // case-insensitive-string = ["%i"] quoted-string
    registry.define(
        "case-insensitive-string",
        concat(vec![opt(lit_ci("%i")), quoted_string.clone()]),
    );

    // case-sensitive-string = "%s" quoted-string
    registry.define(
        "case-sensitive-string",
        concat(vec![lit_ci("%s"), quoted_string.clone()]),
    );

    // quoted-string = DQUOTE *(%x20-21 / %x23-7E) DQUOTE
    registry.define(
        "quoted-string",
        concat(vec![
            dquote.clone(),
            rep(
                0,
                None,
                alt(vec![
                    Literal::range('\x20', '\x21').into(),
                    Literal::range('\x23', '\x7E').into(),
                ]),
            ),
            dquote.clone(),
        ]),
    );
}

/// Build a fresh registry with both the RFC 5234 core rules and the
/// ABNF meta-grammar installed.
pub fn build_meta_grammar() -> RuleRegistry {
    let mut registry = RuleRegistry::new();
    crate::core_rules::install_core_rules(&mut registry);
    install_meta_grammar(&mut registry);
    registry
}
