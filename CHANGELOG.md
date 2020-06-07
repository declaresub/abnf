# Changelog

## 1.1.1

* Imported rules are now created using the source rule's definition, instead of setting the
target rule definition to the source rule.  This was resulting in parse node trees with
unexpected structure.

* RFC 2735 credentials, challenge rules have been restored to their original definitions
now that longest match alternation is the default.

## 1.1.0

* Added class method Rule.from_file which loads a grammar from an ABNF rulelist in a file. https://github.com/declaresub/abnf/issues/2

* Added class attribute Rule.first_match_alternation.  When false, alternation returns the longest 
match, with ties broken by order of match.  When True, alternation returns the first match.

* Added Rule.exclude_rule.  This object method allows one to restrict an existing rule by
excluding values that match another rule.  The initial use case was to exclude keywords
from matching identifiers.

* Parsing is generally faster following some internal tinkering and refactoring.


## 1.0.1

* Unicode characters > 127 expressed as num-val are now correctly parsed. https://github.com/declaresub/abnf/issues/1


## 1.0.0

* Initial release.
