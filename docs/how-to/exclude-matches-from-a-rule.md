# Exclude matches from a rule

ABNF has no "everything except" operator. An RFC that needs one usually says so in
prose — *"an identifier, but not a reserved word"* — and leaves it to the
implementer. `Rule.exclude_rule` is how you express that here.

```python
from abnf import ParseError, Rule

class Grammar(Rule):
    pass

Grammar.create("identifier = ALPHA *(ALPHA / DIGIT)")
Grammar.create('keyword    = "if" / "else" / "while"')

Grammar("identifier").exclude_rule(Grammar("keyword"))

Grammar("identifier").parse_all("counter")   # fine
Grammar("identifier").parse_all("while")     # ParseError
```

The exclusion belongs to the rule, not to the call, so it applies wherever that rule
is referenced — including from inside other rules:

```python
Grammar.create("assignment = identifier *WSP \"=\" *WSP identifier")

Grammar("assignment").parse_all("x = y")       # fine
Grammar("assignment").parse_all("x = while")   # ParseError
```

## Only a complete match excludes

A match is discarded when the text it consumed parses **entirely** as the excluded
rule. Text that merely starts with the excluded rule is unaffected:

```python
Grammar("identifier").parse_all("while")      # ParseError -- exactly the keyword
Grammar("identifier").parse_all("whileEnd")   # fine -- not the keyword
```

This is what you want for the keyword case, and it is worth knowing when the excluded
rule is something more permissive.

## It filters candidates, not the whole parse

`exclude_rule` removes matches from the set a rule offers; it does not abort the
parse. With an ambiguous rule the shorter matches survive:

```python
Grammar.create("word = 1*ALPHA")
Grammar.create('stop = "stop"')
Grammar("word").exclude_rule(Grammar("stop"))

Grammar("word").parse("stop", 0)       # matches "sto" -- 1*ALPHA also matches
                                       # the first three letters, and "sto" is
                                       # not the excluded word
Grammar("word").parse_all("stop")      # ParseError -- no match reaches the end
```

So `parse_all` is what turns an exclusion into a rejection. If you are validating,
you are already using `parse_all` (see {doc}`validate-input`) and this is invisible;
if you are using `parse`, check the returned offset.

## Notes

- Passing a different rule replaces the exclusion; a rule has at most one.
- The excluded rule is looked up when it is set, so define it first.
- Exclusions can be added after the grammar has been used to parse. Earlier releases
  cached parse results across calls, which could hide a newly-added exclusion; that
  cache is now scoped to a single parse (see
  {doc}`../explanation/backtracking-and-caching`).
