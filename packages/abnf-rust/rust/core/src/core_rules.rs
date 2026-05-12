//! RFC 5234 §B.1 core rules, hardcoded.
//!
//! Mirrors the bootstrap block in `_parser_python.py:726-769`.

use crate::alternation::Alternation;
use crate::concatenation::Concatenation;
use crate::literal::Literal;
use crate::parser::ArcParser;
use crate::registry::RuleRegistry;
use crate::repetition::{Repeat, Repetition};

fn lit_cs(value: &str) -> ArcParser {
    Literal::string(value, true).into()
}

fn lit_ci(value: &str) -> ArcParser {
    Literal::string(value, false).into()
}

fn range(lo: char, hi: char) -> ArcParser {
    Literal::range(lo, hi).into()
}

/// Populate `registry` with the 17 RFC 5234 core rules.
pub fn install_core_rules(registry: &mut RuleRegistry) {
    // ALPHA = %x41-5A / %x61-7A    ; A-Z / a-z
    registry.define(
        "ALPHA",
        Alternation::new(vec![range('\x41', '\x5A'), range('\x61', '\x7A')]).into(),
    );

    // BIT = "0" / "1"
    registry.define(
        "BIT",
        Alternation::new(vec![lit_ci("0"), lit_ci("1")]).into(),
    );

    // CHAR = %x01-7F
    registry.define("CHAR", range('\x01', '\x7F'));

    // CTL = %x00-1F / %x7F
    registry.define(
        "CTL",
        Alternation::new(vec![range('\x00', '\x1F'), lit_cs("\x7F")]).into(),
    );

    // CR = %x0D
    registry.define("CR", lit_cs("\x0D"));

    // CRLF = CR LF
    let cr = registry.get_or_create("CR");
    let lf_ref = registry.get_or_create("LF");
    registry.define("CRLF", Concatenation::new(vec![cr, lf_ref]).into());

    // DIGIT = %x30-39
    registry.define("DIGIT", range('\x30', '\x39'));

    // DQUOTE = %x22
    registry.define("DQUOTE", lit_cs("\x22"));

    // HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
    let digit_ref = registry.get_or_create("DIGIT");
    registry.define(
        "HEXDIG",
        Alternation::new(vec![
            digit_ref,
            lit_ci("A"),
            lit_ci("B"),
            lit_ci("C"),
            lit_ci("D"),
            lit_ci("E"),
            lit_ci("F"),
        ])
        .into(),
    );

    // HTAB = %x09
    registry.define("HTAB", lit_cs("\x09"));

    // LF = %x0A
    registry.define("LF", lit_cs("\x0A"));

    // OCTET = %x00-FF
    registry.define("OCTET", range('\x00', '\u{00FF}'));

    // SP = %x20
    registry.define("SP", lit_cs("\x20"));

    // VCHAR = %x21-7E
    registry.define("VCHAR", range('\x21', '\x7E'));

    // WSP = SP / HTAB
    let sp_ref = registry.get_or_create("SP");
    let htab_ref = registry.get_or_create("HTAB");
    registry.define("WSP", Alternation::new(vec![sp_ref, htab_ref]).into());

    // LWSP = *(WSP / CRLF WSP)
    let wsp_ref = registry.get_or_create("WSP");
    let crlf_ref = registry.get_or_create("CRLF");
    let crlf_wsp: ArcParser = Concatenation::new(vec![crlf_ref, wsp_ref.clone()]).into();
    registry.define(
        "LWSP",
        Repetition::new(
            Repeat::new(0, None),
            Alternation::new(vec![wsp_ref, crlf_wsp]).into(),
        )
        .into(),
    );
}
