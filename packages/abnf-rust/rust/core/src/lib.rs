//! Pure-Rust ABNF parser engine.
//!
//! No Python dependency.  The PyO3 bindings in the sibling
//! `abnf-rust-ext` crate adapt this crate's API to Python; the engine
//! itself is consumable from any Rust caller.
//!
//! The module mirrors the pure-Python implementation in
//! `abnf._parser_python` (`src/abnf/_parser_python.py` in the parent
//! repository) line-for-line in semantics: same combinator algebra,
//! same enumeration-of-matches behaviour, same longest-match-wins
//! tie-breaking in `Alternation`, same cache shape on `Repetition`.
//!
//! Offsets in `LiteralNode` and `Match` are **byte** offsets into the
//! `&str` source.  The PyO3 wrapper translates them to Python
//! code-point offsets at the FFI boundary.

#![deny(unsafe_op_in_unsafe_fn)]

mod alternation;
mod cache;
mod casefold;
mod concatenation;
mod core_rules;
mod error;
mod literal;
mod matcher;
mod meta_grammar;
mod node;
mod option;
mod parser;
mod prose;
mod registry;
mod repetition;
mod rule;
mod visitor;

pub use alternation::Alternation;
pub use cache::ParseCache;
pub use concatenation::Concatenation;
pub use core_rules::install_core_rules;
pub use meta_grammar::{build_meta_grammar, install_meta_grammar};
pub use error::ParseError;
pub use literal::{Literal, LiteralKind};
pub use matcher::Match;
pub use node::{LiteralNode, Node, NodeKind};
pub use option::OptionParser;
pub use parser::{ArcParser, ParserOp};
pub use prose::Prose;
pub use registry::RuleRegistry;
pub use repetition::{Repeat, Repetition};
pub use rule::NamedRule;
pub use visitor::{parse_rule_source, parse_rulelist_source, visit_rule, visit_rulelist, DefinedAs};
