//! `bootstrap(rule_cls)` — populate the Python `Rule` /
//! `ABNFGrammarRule` registry with Rust-backed combinator trees.
//!
//! The function walks the Rust meta-grammar registry (built once via
//! [`abnf_core::build_meta_grammar`]) and, for every named rule,
//! invokes `rule_cls(name, py_definition)`.  Python's
//! `Rule.__new__` caches the resulting object under
//! `_obj_map[(cls, name.casefold())]`, so after this call returns
//! every lookup of `ABNFGrammarRule("rulelist")` etc. resolves to
//! the Rust-backed parser.
//!
//! Core RFC 5234 rules (`ALPHA`, `BIT`, ...) are installed against
//! `rule_cls.__mro__[1]` (the base `Rule` class) rather than
//! `rule_cls` itself, matching the namespacing the pure-Python
//! implementation uses in `_parser_python.py:726-769`.

use std::collections::HashSet;

use pyo3::prelude::*;
use pyo3::types::PyType;

use abnf_core::build_meta_grammar;

use crate::parsers::wrap_arc_parser;

/// Names that belong on the base `Rule` class (RFC 5234 §B.1).
fn core_rule_names() -> HashSet<&'static str> {
    [
        "alpha", "bit", "char", "ctl", "cr", "crlf", "digit", "dquote", "hexdig", "htab", "lf",
        "lwsp", "octet", "sp", "vchar", "wsp",
    ]
    .into_iter()
    .collect()
}

#[pyfunction]
pub fn bootstrap(py: Python<'_>, rule_cls: &Bound<'_, PyType>) -> PyResult<()> {
    let registry = build_meta_grammar();
    let core_names = core_rule_names();

    // The base `Rule` class is `rule_cls.__mro__[1]` (since rule_cls
    // is expected to be `ABNFGrammarRule`, a direct subclass).
    let mro = rule_cls.getattr("__mro__")?;
    let rule_base = mro.get_item(1)?.cast_into::<PyType>()?;

    for (name, named_rule) in registry.iter() {
        let definition = match named_rule.definition() {
            Some(def) => def,
            None => continue,
        };
        let py_def = wrap_arc_parser(py, definition)?;
        let target_cls = if core_names.contains(name) {
            &rule_base
        } else {
            rule_cls
        };
        // The original case of the rule's name is preserved in
        // `named_rule.name`; pass that rather than the case-folded
        // registry key so that downstream display strings are
        // recognisable.
        let original_name = named_rule.name.as_ref();
        target_cls.call1((original_name, py_def))?;
    }
    Ok(())
}
