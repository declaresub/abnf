//! `RuleRegistry` — named-rule namespace.

use std::collections::HashMap;
use std::sync::Arc;

use crate::casefold::casefold;
use crate::parser::{arc, ArcParser};
use crate::rule::NamedRule;

#[derive(Debug, Default)]
pub struct RuleRegistry {
    rules: HashMap<String, Arc<NamedRule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a parser reference for `name`.  The result is an
    /// `ArcParser` ready to compose into a combinator tree; each call
    /// returns a fresh `Arc<Parser::Rule(...)>` whose inner
    /// `NamedRule` is shared with every other reference to the same
    /// name.
    pub fn get_or_create(&mut self, name: &str) -> ArcParser {
        arc(self.get_or_create_rule(name))
    }

    /// Get or create the underlying `NamedRule` (for setting its
    /// definition).
    pub fn get_or_create_rule(&mut self, name: &str) -> Arc<NamedRule> {
        let key = casefold(name);
        self.rules
            .entry(key)
            .or_insert_with(|| Arc::new(NamedRule::new(name)))
            .clone()
    }

    /// Define a rule.  Creates a placeholder if necessary, then sets
    /// its definition.
    pub fn define(&mut self, name: &str, definition: ArcParser) -> Arc<NamedRule> {
        let rule = self.get_or_create_rule(name);
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
