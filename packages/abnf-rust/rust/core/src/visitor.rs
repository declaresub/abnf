//! ABNF parse-tree → combinator-tree translation.

use std::sync::Arc;

use crate::alternation::Alternation;
use crate::concatenation::Concatenation;
use crate::error::ParseError;
use crate::literal::Literal;
use crate::node::{Node, NodeKind};
use crate::option::OptionParser;
use crate::parser::ArcParser;
use crate::prose::Prose;
use crate::registry::RuleRegistry;
use crate::repetition::{Repeat, Repetition};
use crate::rule::NamedRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinedAs {
    Define,
    Extend,
}

/// Walk a `rulelist` node, installing each rule into `registry`.
pub fn visit_rulelist(node: &Node, registry: &mut RuleRegistry) -> Vec<Arc<NamedRule>> {
    let mut result = Vec::new();
    for child in node.children.iter() {
        if let NodeKind::Internal(inner) = child {
            if inner.name.as_ref() == "rule" {
                result.push(visit_rule(inner, registry));
            }
        }
    }
    result
}

/// Walk a `rule` node, install its definition, and return the handle.
pub fn visit_rule(node: &Node, registry: &mut RuleRegistry) -> Arc<NamedRule> {
    let mut name: Option<Arc<str>> = None;
    let mut defined_as: DefinedAs = DefinedAs::Define;
    let mut elements_parser: Option<ArcParser> = None;

    for child in node.children.iter() {
        let NodeKind::Internal(inner) = child else { continue };
        match inner.name.as_ref() {
            "rulename" => name = Some(rulename_text(inner)),
            "defined-as" => defined_as = visit_defined_as(inner),
            "elements" => elements_parser = Some(visit_elements(inner, registry)),
            _ => {}
        }
    }

    let name = name.expect("rule: missing rulename");
    let elements_parser = elements_parser.expect("rule: missing elements");

    let final_def: ArcParser = match defined_as {
        DefinedAs::Define => elements_parser,
        DefinedAs::Extend => {
            let existing = registry
                .get_or_create_rule(name.as_ref())
                .definition()
                .expect("=/ used on undefined rule");
            Alternation::new(vec![existing, elements_parser]).into()
        }
    };
    registry.define(name.as_ref(), final_def)
}

fn visit_defined_as(node: &Node) -> DefinedAs {
    let trimmed = node.value();
    let trimmed = trimmed.trim();
    if trimmed == "=/" {
        DefinedAs::Extend
    } else {
        DefinedAs::Define
    }
}

fn visit_elements(node: &Node, registry: &mut RuleRegistry) -> ArcParser {
    for child in node.children.iter() {
        let NodeKind::Internal(inner) = child else { continue };
        if inner.name.as_ref() == "alternation" {
            return visit_alternation(inner, registry);
        }
    }
    panic!("visit_elements: alternation child missing")
}

fn visit_alternation(node: &Node, registry: &mut RuleRegistry) -> ArcParser {
    let mut parts: Vec<ArcParser> = Vec::new();
    for child in node.children.iter() {
        let NodeKind::Internal(inner) = child else { continue };
        if inner.name.as_ref() == "concatenation" {
            parts.push(visit_concatenation(inner, registry));
        }
    }
    if parts.len() == 1 {
        parts.into_iter().next().expect("checked len")
    } else {
        Alternation::new(parts).into()
    }
}

fn visit_concatenation(node: &Node, registry: &mut RuleRegistry) -> ArcParser {
    let mut parts: Vec<ArcParser> = Vec::new();
    for child in node.children.iter() {
        let NodeKind::Internal(inner) = child else { continue };
        if inner.name.as_ref() == "repetition" {
            parts.push(visit_repetition(inner, registry));
        }
    }
    if parts.len() == 1 {
        parts.into_iter().next().expect("checked len")
    } else {
        Concatenation::new(parts).into()
    }
}

fn visit_repetition(node: &Node, registry: &mut RuleRegistry) -> ArcParser {
    let mut repeat: Option<Repeat> = None;
    let mut element: Option<ArcParser> = None;
    for child in node.children.iter() {
        let NodeKind::Internal(inner) = child else { continue };
        match inner.name.as_ref() {
            "repeat" => repeat = Some(visit_repeat(inner)),
            "element" => element = Some(visit_element(inner, registry)),
            _ => {}
        }
    }
    let element = element.expect("repetition: missing element");
    match repeat {
        Some(r) => Repetition::new(r, element).into(),
        None => element,
    }
}

fn visit_repeat(node: &Node) -> Repeat {
    let mut min_src = String::new();
    let mut saw_star = false;
    let mut max_src = String::new();
    for child in node.children.iter() {
        match child {
            NodeKind::Internal(inner) => {
                if inner.name.as_ref() == "DIGIT" {
                    if saw_star {
                        max_src.push_str(&inner.value());
                    } else {
                        min_src.push_str(&inner.value());
                    }
                }
            }
            NodeKind::Literal(lit) => {
                if lit.value.as_ref() == "*" {
                    saw_star = true;
                }
            }
        }
    }
    let min = if min_src.is_empty() {
        0
    } else {
        min_src.parse::<usize>().unwrap_or(0)
    };
    if saw_star {
        let max = if max_src.is_empty() {
            None
        } else {
            max_src.parse::<usize>().ok()
        };
        Repeat::new(min, max)
    } else {
        Repeat::new(min, Some(min))
    }
}

fn visit_element(node: &Node, registry: &mut RuleRegistry) -> ArcParser {
    for child in node.children.iter() {
        let NodeKind::Internal(inner) = child else { continue };
        return match inner.name.as_ref() {
            "rulename" => visit_rulename(inner, registry),
            "group" => visit_group(inner, registry),
            "option" => visit_option(inner, registry),
            "char-val" => visit_char_val(inner),
            "num-val" => visit_num_val(inner),
            "prose-val" => visit_prose_val(inner, registry),
            other => panic!("visit_element: unexpected child '{other}'"),
        };
    }
    panic!("visit_element: empty children")
}

fn visit_rulename(node: &Node, registry: &mut RuleRegistry) -> ArcParser {
    registry.get_or_create(rulename_text(node).as_ref())
}

fn visit_group(node: &Node, registry: &mut RuleRegistry) -> ArcParser {
    for child in node.children.iter() {
        let NodeKind::Internal(inner) = child else { continue };
        if inner.name.as_ref() == "alternation" {
            return visit_alternation(inner, registry);
        }
    }
    panic!("visit_group: alternation child missing")
}

fn visit_option(node: &Node, registry: &mut RuleRegistry) -> ArcParser {
    for child in node.children.iter() {
        let NodeKind::Internal(inner) = child else { continue };
        if inner.name.as_ref() == "alternation" {
            let alt = visit_alternation(inner, registry);
            return OptionParser::new(alt).into();
        }
    }
    panic!("visit_option: alternation child missing")
}

fn visit_prose_val(node: &Node, registry: &mut RuleRegistry) -> ArcParser {
    let raw = node.value();
    let inner = if raw.starts_with('<') && raw.ends_with('>') {
        &raw[1..raw.len() - 1]
    } else {
        raw.as_str()
    };
    if !inner.is_empty() && looks_like_rulename(inner) {
        return registry.get_or_create(inner);
    }
    Prose.into()
}

fn looks_like_rulename(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else { return false };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
}

// ---------- char-val (RFC 7405) ----------

fn visit_char_val(node: &Node) -> ArcParser {
    for child in node.children.iter() {
        let NodeKind::Internal(inner) = child else { continue };
        return match inner.name.as_ref() {
            "case-insensitive-string" => {
                let s = quoted_string_value(inner);
                Literal::string(s, false).into()
            }
            "case-sensitive-string" => {
                let s = quoted_string_value(inner);
                Literal::string(s, true).into()
            }
            other => panic!("visit_char_val: unexpected child '{other}'"),
        };
    }
    panic!("visit_char_val: empty children")
}

fn quoted_string_value(node: &Node) -> String {
    for child in node.children.iter() {
        let NodeKind::Internal(inner) = child else { continue };
        if inner.name.as_ref() == "quoted-string" {
            let raw = inner.value();
            if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
                return raw[1..raw.len() - 1].to_string();
            }
            return raw;
        }
    }
    panic!("quoted_string_value: no quoted-string child")
}

// ---------- num-val ----------

fn visit_num_val(node: &Node) -> ArcParser {
    for child in node.children.iter() {
        let NodeKind::Internal(inner) = child else { continue };
        return match inner.name.as_ref() {
            "bin-val" => parse_num_val(inner, "BIT", 2),
            "dec-val" => parse_num_val(inner, "DIGIT", 10),
            "hex-val" => parse_num_val(inner, "HEXDIG", 16),
            other => panic!("visit_num_val: unexpected child '{other}'"),
        };
    }
    panic!("visit_num_val: empty children")
}

fn parse_num_val(node: &Node, digit_node_name: &str, base: u32) -> ArcParser {
    let mut iter = node.children.iter();
    iter.next();

    let mut buffer = String::new();
    let mut groups: Vec<String> = Vec::new();
    let mut range_op = false;
    let mut second_buffer = String::new();
    let mut current_buffer: &mut String = &mut buffer;

    for child in iter {
        match child {
            NodeKind::Internal(inner) if inner.name.as_ref() == digit_node_name => {
                current_buffer.push_str(&inner.value());
            }
            NodeKind::Literal(lit) => match lit.value.as_ref() {
                "." => {
                    groups.push(std::mem::take(current_buffer));
                }
                "-" => {
                    range_op = true;
                    current_buffer = &mut second_buffer;
                }
                _ => {}
            },
            _ => {}
        }
    }
    if range_op {
        let first_char = decode_codepoint(&buffer, base);
        let last_char = decode_codepoint(&second_buffer, base);
        return Literal::range(first_char, last_char).into();
    }
    if !buffer.is_empty() {
        groups.push(buffer);
    }
    let value: String = groups
        .iter()
        .map(|s| decode_codepoint(s, base))
        .collect();
    Literal::string(value, true).into()
}

fn decode_codepoint(digits: &str, base: u32) -> char {
    let n = u32::from_str_radix(digits, base).expect("invalid num-val digits");
    char::from_u32(n).expect("num-val out of Unicode range")
}

fn rulename_text(node: &Node) -> Arc<str> {
    Arc::from(node.value())
}

// ---------- end-to-end entry points ----------

pub fn parse_rule_source(
    source: &str,
    registry: &mut RuleRegistry,
) -> Result<Arc<NamedRule>, ParseError> {
    let mut src = source.to_string();
    if !src.ends_with("\r\n") {
        src.push_str("\r\n");
    }
    let rule_rule = registry
        .get("rule")
        .expect("meta-grammar not installed: 'rule' missing");
    let matches = rule_rule.lparse(&src, 0)?;
    let mut best = matches;
    best.sort_by_key(|m| std::cmp::Reverse(m.start));
    let top = best
        .into_iter()
        .next()
        .ok_or_else(|| ParseError::new("parse_rule_source: no match", 0))?;
    let parse_tree = match top.nodes.into_iter().next() {
        Some(NodeKind::Internal(n)) => n,
        _ => return Err(ParseError::new("parse_rule_source: unexpected match shape", 0)),
    };
    Ok(visit_rule(&parse_tree, registry))
}

pub fn parse_rulelist_source(
    source: &str,
    registry: &mut RuleRegistry,
) -> Result<Vec<Arc<NamedRule>>, ParseError> {
    let normalised = normalise_crlf(source);
    let rulelist_rule = registry
        .get("rulelist")
        .expect("meta-grammar not installed: 'rulelist' missing");
    let matches = rulelist_rule.lparse(&normalised, 0)?;
    let mut best = matches;
    best.sort_by_key(|m| std::cmp::Reverse(m.start));
    let top = best
        .into_iter()
        .next()
        .ok_or_else(|| ParseError::new("parse_rulelist_source: no match", 0))?;
    if top.start < normalised.len() {
        return Err(ParseError::new(
            "parse_rulelist_source: incomplete parse",
            top.start,
        ));
    }
    let parse_tree = match top.nodes.into_iter().next() {
        Some(NodeKind::Internal(n)) => n,
        _ => {
            return Err(ParseError::new(
                "parse_rulelist_source: unexpected match shape",
                0,
            ));
        }
    };
    Ok(visit_rulelist(&parse_tree, registry))
}

fn normalise_crlf(src: &str) -> String {
    let trimmed = src.trim_end();
    let mut out = String::with_capacity(trimmed.len() + 2);
    for ch in trimmed.chars() {
        if ch == '\r' {
            continue;
        }
        if ch == '\n' {
            out.push_str("\r\n");
        } else {
            out.push(ch);
        }
    }
    out.push_str("\r\n");
    out
}
