//! `RuleRegistry` — named-rule namespace.
//!
//! Mirrors the role of `Rule._obj_map` on the Python side: maps a rule
//! name to the `NamedRule` that stands for it.  References to a name
//! that hasn't been defined yet return a placeholder rule whose
//! definition can be filled in later, supporting forward references in
//! the meta-grammar and in user-supplied `rulelist` inputs.
//!
//! Names are compared case-insensitively via Unicode case-folding,
//! matching Python's `str.casefold()` used as the registry key.

use std::collections::HashMap;
use std::sync::Arc;

use crate::casefold::casefold;
use crate::parser::ArcParser;
use crate::rule::NamedRule;

#[derive(Debug, Default)]
pub struct RuleRegistry {
    rules: HashMap<String, Arc<NamedRule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the rule named `name`, creating an undefined placeholder
    /// if it doesn't yet exist.  Multiple `get_or_create` calls with
    /// names that case-fold to the same key return the same
    /// `Arc<NamedRule>`.
    pub fn get_or_create(&mut self, name: &str) -> Arc<NamedRule> {
        let key = casefold(name);
        self.rules
            .entry(key)
            .or_insert_with(|| Arc::new(NamedRule::new(name)))
            .clone()
    }

    /// Define a rule.  Creates a placeholder if necessary, then sets
    /// its definition.  Returns the rule handle.
    pub fn define(&mut self, name: &str, definition: ArcParser) -> Arc<NamedRule> {
        let rule = self.get_or_create(name);
        rule.set_definition(definition);
        rule
    }

    /// Look up a previously-created rule without auto-creating one.
    pub fn get(&self, name: &str) -> Option<Arc<NamedRule>> {
        self.rules.get(&casefold(name)).cloned()
    }

    /// Iterate over the (case-folded name, rule) pairs in the registry.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Arc<NamedRule>)> {
        self.rules.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}
