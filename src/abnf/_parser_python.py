from __future__ import annotations

import abc
import contextvars
import operator
import pathlib
import typing
import warnings
from collections import OrderedDict
from collections.abc import Generator
from weakref import WeakSet

from .typing import Protocol, runtime_checkable

Source = str
Nodes = list["Node"]

#: Folds the 26 ASCII uppercase letters and nothing else.
_ASCII_FOLD_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
)


def _ascii_fold(value: str) -> str:
    """Case-fold over US-ASCII only.

    RFC 5234 §2.3 makes literals case-insensitive and says the character set
    for them is US-ASCII, so case-insensitivity is defined over ASCII and
    nothing else.  `str.casefold()`, used here previously, is full Unicode:
    it matched a source of `'\u017f'` (long s) against `"s"`, `'\u212a'`
    (Kelvin sign) against `"k"`, and `'ß'` against `"ss"` -- input a grammar
    written in ASCII should reject.

    Folding only ASCII also makes the operation length-preserving, which
    Unicode folding is not.  The old behaviour therefore depended on
    position: `"ss"` matched a lone `'ß'`, but `"ss" "x"` rejected `'ßx'`,
    because the comparison folds a fixed-width window of the source.

    Fast path via `str.lower`, which for an ASCII string *is* the ASCII
    fold; CPython flags ASCII-ness on the object, so the test is free.
    """

    return value.lower() if value.isascii() else value.translate(_ASCII_FOLD_TABLE)


class Match:
    """A span of consumed source, identified by its text and end offset.

    Two matches are equal when they consumed the same text and ended at
    the same offset, whatever node structure produced it -- an ambiguous
    grammar can reach the same span more than one way, and the parser
    treats those as one result.
    """

    __slots__ = ("nodes", "start")

    def __init__(self, nodes: Nodes, start: int):
        self.nodes = nodes
        self.start = start

    def _value(self) -> str:
        return "".join(node.value for node in self.nodes)

    def __hash__(self) -> int:
        # Not memoised.  Nothing in the parser hashes a `Match` -- both
        # `Repetition` and `Rule.lparse` deduplicate by end offset -- so a
        # cached slot would cost eight bytes on every match built (a few
        # thousand per parse) to speed up an operation the library never
        # performs.  It also could not be invalidated: `nodes` is a plain
        # mutable list, so a memo went stale the moment a caller touched it.
        return hash((self._value(), self.start))

    def __str__(self):
        return f"Match(value={self._value()}, start={self.start})"

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, self.__class__):
            return False
        # Compare the values, not their hashes.  Hash equality is only
        # evidence of equality; two matches that collided would have
        # compared equal, and `__eq__` is the one place that has to be
        # exact.  `start` differs far more often than the text does, so
        # checking it first usually avoids building either string.
        return self.start == __o.start and self._value() == __o._value()


MatchSet = set[Match]
Matches = typing.Iterator[Match]


def sorted_by_longest_match(matches: typing.Iterable[Match]) -> list[Match]:
    return sorted(matches, key=lambda item: item.start, reverse=True)


def next_longest(matches: typing.Iterable[Match]) -> Generator[Match, None, None]:
    materialised = list(matches)
    if len(materialised) > 1:
        yield from sorted_by_longest_match(materialised)
    else:
        yield from materialised


@runtime_checkable
class Parser(Protocol):
    # def parse(
    #    self, source: str, start: int
    # ) -> tuple[Nodes, int]:  # pragma: no cover
    #   ...
    def lparse(self, source: Source, start: int) -> Matches: ...  # pragma: no cover


ParseCacheKey = tuple[str, int]


class _CachedParseError:
    """Lightweight failure marker stored in `ParseCache`.

    Caching the original `ParseError` instance and re-raising it on every
    hit accumulates traceback frames on a shared exception object and
    leaks any user-attached state across cache hits.  We instead record
    the constructor arguments and rebuild a fresh `ParseError` each time.
    """

    __slots__ = ("args", "parser", "start")

    def __init__(self, parser: Parser, start: int, args: tuple[typing.Any, ...]):
        self.parser = parser
        self.start = start
        self.args = args


# Repetition now stores its match list as an ordered `list[Match]`
# (deduplicated by end position) rather than `set[Match]`, sidestepping
# the per-Match value-hashing cost.  `MatchSet` remains in the union
# for backward compatibility with any external code that stored sets.
ParseCacheValue = list[Match] | MatchSet | _CachedParseError

# Per-parse memo.  `Rule.parse` binds `(source, {})` for the duration of one
# parse and `Repetition` memoises into that dict, so nothing survives the call
# that created it.  `ContextVar.set` returns a token and `reset(token)` restores
# the previous binding, which gives nesting for free: `Rule.lparse`'s `exclude`
# check runs `parse_all` on a *different* source mid-parse, and that inner parse
# simply binds its own memo and gives this one back on the way out.
#
# A ContextVar rather than a threading.local: it is cheaper to read (measured
# 29.9ns vs 34.6ns), and it isolates asyncio tasks as well as threads.  Only
# `Rule.parse` ever writes it -- never a generator, whose `set` would leak into
# the caller's context between yields.
#: Keyed on ``(parser, start)``.  The parser is the object itself rather than
#: its ``id``: an id is unique only among live objects, so a parser freed
#: mid-parse could have its address reused and inherit the dead one's entries
#: (issue #262).  Holding it keeps it alive for exactly the life of the memo,
#: which is one ``Rule.parse`` call.
_ParseMemoKey = tuple[object, int]
_ParseMemo = tuple[Source, dict[_ParseMemoKey, ParseCacheValue]]
_parse_memo: contextvars.ContextVar[_ParseMemo | None] = contextvars.ContextVar(
    "abnf_parse_memo", default=None
)


_CACHE_DEPRECATION = (
    "The parse cache is now scoped to a single parse and discarded when that "
    "parse returns, so {what} no longer has any effect and can be removed. "
    "For reuse across calls, memoise at the call site -- e.g. "
    "functools.lru_cache on your own wrapper -- which is both bounded and "
    "far faster, since it skips the parse entirely rather than replaying "
    "sub-results."
)


class _ParseCacheMeta(abc.ABCMeta):
    """Metaclass so that assigning the vestigial knob can be flagged.

    `max_cache_size` is a plain class attribute, so there is no other hook for
    telling a caller their configuration stopped mattering.  Derives from
    `ABCMeta` because `ParseCache` is a `MutableMapping`.
    """

    def __setattr__(cls, name: str, value: typing.Any) -> None:
        if name == "max_cache_size":
            warnings.warn(
                _CACHE_DEPRECATION.format(what="ParseCache.max_cache_size"),
                DeprecationWarning,
                stacklevel=2,
            )
        super().__setattr__(name, value)


class ParseCache(
    typing.MutableMapping[ParseCacheKey, ParseCacheValue],
    metaclass=_ParseCacheMeta,
):
    """A mapping that used to memoise `Repetition` results across parses.

    .. deprecated::
        The parser no longer uses this class; memoisation moved into a
        per-parse context (`_parse_memo`).  The class remains importable, and
        works as an ordinary mapping, so existing imports keep functioning.
    """

    max_cache_size: int | None = None
    objects: WeakSet[ParseCache] = WeakSet()

    def __new__(cls, max_size: int | None = None):
        obj = super().__new__(cls)
        cls.objects.add(obj)
        return obj

    def __init__(self, max_size: int | None = None):
        self.dict: OrderedDict[ParseCacheKey, ParseCacheValue] = OrderedDict()
        if max_size is None:
            max_size = self.max_cache_size
        if max_size and max_size < 0:
            msg = "max size must be non-negative."
            raise ValueError(msg)
        self.max_size = max_size
        self.hits = 0
        self.misses = 0

    def __getitem__(self, key: ParseCacheKey) -> ParseCacheValue:
        try:
            value = self.dict[key]
        except KeyError:
            self.misses = self.misses + 1
            raise
        else:
            self.hits = self.hits + 1
            self.dict.move_to_end(key)
            return value

    def __setitem__(self, key: ParseCacheKey, value: ParseCacheValue):
        # here we want to expel least recently used entries, defined to the first entries in the order.
        self.dict[key] = value
        if self.max_size and len(self.dict) > self.max_size:
            self.dict.popitem(last=False)

    def __delitem__(self, key: ParseCacheKey):
        del self.dict[key]

    def __iter__(self):
        return self.dict.__iter__()

    def __len__(self):
        return len(self.dict)

    def __hash__(self):
        return id(self)

    def __eq__(self, __o: object) -> bool:
        return hash(self) == hash(__o)

    def __str__(self):
        return f"{self.__class__.__name__}(max_size = {self.max_size}, size = {len(self)}, misses = {self.misses}, hits = {self.hits})"

    @classmethod
    def clear_caches(cls):
        """Clear every live `ParseCache`.

        .. deprecated::
            Nothing in the parser holds a `ParseCache` any more, so there is
            no parser state left for this to clear.  It still empties any
            instances the caller made themselves.
        """
        warnings.warn(
            _CACHE_DEPRECATION.format(what="ParseCache.clear_caches()"),
            DeprecationWarning,
            stacklevel=2,
        )
        for obj in cls.objects:
            obj.dict = OrderedDict()
            obj.hits = 0
            obj.misses = 0

    @classmethod
    def list(cls):
        yield from cls.objects


class Alternation:
    """Implements the ABNF alternation operator. -- Alternation(parser1, parser2, ...)
    returns a parser that invokes parser1, parser2, ... in turn and returns the result
    of the first successful parse.."""

    str_template = "Alternation(%s)"

    def __init__(self, *parsers: Parser, first_match: bool = False):
        self.parsers = list(parsers)
        self.first_match = first_match

    def lparse(self, source: Source, start: int) -> Matches:
        # Collect matches from every alternative, then yield them
        # longest-first.  Doing the sort here (rather than once per
        # `Rule.parse` call as `set + next_longest`) lets downstream
        # consumers — notably `Rule.lparse` — short-circuit on the
        # first (longest) match without losing alternatives that
        # might be longer.
        accumulated: list[Match] = []
        match_found = False
        for parser in self.parsers:
            try:
                for item in parser.lparse(source, start):
                    accumulated.append(item)
                    match_found = True
            except ParseError:
                continue
            if self.first_match:
                # First-match mode: preserve the parser-order of the
                # first matching parser; don't reorder by length.
                if match_found:
                    yield from accumulated
                return
        if not match_found:
            raise ParseError(self, start)
        # Skip the sort on the common deterministic single-match
        # case — most rules in real grammars take a single
        # alternative and the sort overhead adds up across nested
        # combinators.
        if len(accumulated) > 1:
            accumulated.sort(key=lambda m: m.start, reverse=True)
        yield from accumulated

    def __str__(self):
        return self.str_template % ", ".join(map(str, self.parsers))


class Concatenation:
    """Implements the ABNF concatention operation. Concatention(parser1, parser2, ...)
    returns a parser that invokes parser1, parser2, ... in turn and returns a list of Nodes
    if every parser succeeds.
    """

    str_template = "Concatenation(%s)"

    def __init__(self, *parsers: Parser):
        self.parsers = parsers

    def lparse(self, source: Source, start: int):
        match_list: list[Match] = [Match([], start)]
        for parser in self.parsers:
            current_match_list: list[Match] = []
            for match in match_list:
                try:  # noqa: SIM105
                    current_match_list.extend(
                        [
                            Match(match.nodes + m.nodes, m.start)
                            for m in parser.lparse(source, match.start)
                        ]
                    )
                except ParseError:  # noqa: PERF203
                    pass
            if current_match_list:
                match_list = current_match_list
            else:
                raise ParseError(self, start)
        if len(match_list) > 1:
            yield from sorted_by_longest_match(match_list)
        else:
            yield from match_list

    def __str__(self):
        return self.str_template % ", ".join(map(str, self.parsers))


class Repeat:
    """Implements the ABNF Repeat operator for Repetition."""

    def __init__(self, min: int = 0, max: int | None = None):
        # `3*2` is an impossible range.  Silently treating it as `3*`
        # -- which is what an unvalidated max does, since the loop
        # never reaches an upper bound it has already passed -- turns
        # a typo for `2*3` into unbounded repetition with no
        # diagnostic.  Reject it where the grammar is built.
        if max is not None and max < min:
            msg = (
                f"Repeat max ({max}) is less than min ({min}); "
                f"a repetition of {min}*{max} can never match."
            )
            raise GrammarError(msg)
        self.min = min
        self.max = max

    def __str__(self):
        _min = self.min
        _max = self.max if self.max is not None else "None"
        return f"Repeat({_min}, {_max})"


class Repetition:
    """Implements the ABNF Repetition operation."""

    def __init__(self, repeat: Repeat, element: Parser):
        self.repeat = repeat
        self.element = element
        # The `min` prefix parser depends only on `element` and `repeat.min`,
        # both fixed here, so build it once rather than on every cache miss --
        # `1*X` is the most common repetition there is.  Building it per miss
        # also meant each failure blamed a different (equal-behaving) parser
        # instance, which only went unnoticed because the old cross-call cache
        # replayed the first one.  Nothing in the library mutates `Repeat`
        # after construction; a caller who does would need to rebuild this.
        self._min_parser = (
            Concatenation(*([element] * repeat.min)) if repeat.min else None
        )

    def lparse(self, source: Source, start: int) -> Matches:
        # Memoise into the current parse's context rather than into
        # per-instance state.  Because the memo dies with the parse, the
        # grammar cannot change underneath it, so there is nothing to
        # invalidate -- which is what made the old `(source, start)` cache
        # return stale results after `=/`, `exclude_rule`, or a
        # `first_match_alternation` flip.
        #
        # `ctx[0] is source` enforces the invariant the key relies on: one
        # memo, one source, so `start` alone identifies a position.  A direct
        # `lparse` call outside any parse, or one that somehow reaches a
        # different source under an active memo, falls back to a memo scoped
        # to this call -- correct either way, since the memo is only ever an
        # optimisation.
        ctx = _parse_memo.get()
        memo = ctx[1] if ctx is not None and ctx[0] is source else {}

        # Key on the object, not `id(self)`: an id is unique only among live
        # objects, so a `Repetition` freed mid-parse could have its address
        # reused and hand its cached matches to a different parser.  Holding
        # the object keeps it alive for exactly as long as the memo, which is
        # this one parse.  See https://github.com/declaresub/abnf/issues/262 .
        cache_key = (self, start)
        cached_matchset = memo.get(cache_key)
        if cached_matchset is not None:
            if isinstance(cached_matchset, _CachedParseError):
                raise ParseError(
                    cached_matchset.parser,
                    cached_matchset.start,
                    *cached_matchset.args,
                )
            # Already longest-first: the list is sorted once, before it
            # goes into the memo, rather than on every hit.  A cold
            # rfc5322 parse takes ~1,700 hits, each of which used to
            # pay a list copy and a sort of a list that never changes.
            yield from cached_matchset
            return

        # De-duplicate by `Match.start` (i.e. by end position) rather
        # than via `set[Match]` membership.  Two matches that consume
        # the same source span end at the same offset, so dedup-by-
        # start mirrors `(value, start)` set semantics without paying
        # the per-Match value-string materialisation that
        # `Match.__hash__` requires.  `match_list` preserves order
        # for the final longest-first yield.
        match_list: list[Match]
        seen_starts: set[int]
        if self.repeat.min == 0:
            match_list = [Match([], start)]
            seen_starts = {start}
        else:
            # `_min_parser` is non-None exactly when `repeat.min` is non-zero,
            # which is this branch.
            min_parser = typing.cast("Parser", self._min_parser)
            try:
                # If this raises a ParseError the minimum match was not reached.
                match_list = list(min_parser.lparse(source, start))
            except ParseError as exc:
                memo[cache_key] = _CachedParseError(exc.parser, exc.start, exc.args)
                raise
            seen_starts = set()
            deduped: list[Match] = []
            for m in match_list:
                if m.start in seen_starts:
                    continue
                seen_starts.add(m.start)
                deduped.append(m)
            match_list = deduped

        last_match_set = list(match_list)
        match_count = self.repeat.min

        while True:
            if self.repeat.max is not None and match_count == self.repeat.max:
                break

            new_match_set: list[Match] = []
            new_seen_starts: set[int] = set()
            for match in last_match_set:
                try:
                    g = self.element.lparse(source, match.start)
                    for m in g:
                        if m.start in seen_starts or m.start in new_seen_starts:
                            continue
                        new_seen_starts.add(m.start)
                        new_match_set.append(Match(match.nodes + m.nodes, m.start))
                except ParseError:
                    pass

            if new_match_set:
                match_count = match_count + 1
                seen_starts.update(new_seen_starts)
                match_list.extend(new_match_set)
                last_match_set = new_match_set
            else:
                break

        # Sort in place, once, so both this yield and every later hit
        # can iterate the stored list directly.  Same comparison and
        # same stable sort `next_longest` applied, so the order is
        # unchanged -- it just happens once instead of per hit.
        if len(match_list) > 1:
            match_list.sort(key=lambda match: match.start, reverse=True)
        memo[cache_key] = match_list
        yield from match_list

    def __str__(self):
        return f"Repetition({self.repeat}, {self.element})"


class Option:
    """Implements the ABNF Option operation."""

    str_template = "Option(%s)"

    def __init__(self, alternation: Parser):
        self.alternation = alternation
        self.parser = Repetition(Repeat(0, 1), alternation)

    def lparse(self, source: Source, start: int) -> Matches:
        """
        :param source: source data
        :type str:
        :param start: offset at which to begin parsing.
        :returns: parse tree, new offset at which to continue parsing
        :rtype: Node, int
        :raises ParseError:
        """
        return self.parser.lparse(source, start)

    def __str__(self):
        return self.str_template % str(self.alternation)


class Literal:
    """Represents a terminal literal value."""

    def __init__(
        self,
        value: str | tuple[str, str],
        case_sensitive: bool = False,
    ):
        """
        value is either a string to be matched, or a two-element tuple representing an
        inclusive range; e.g. ('a', 'z') matches all letters a-z.
        """

        if not (
            isinstance(value, str)
            or (
                isinstance(value, tuple)  # type: ignore
                and len(value) == 2
                and isinstance(value[0], str)  # type: ignore
                and isinstance(value[1], str)  # type: ignore
            )
        ):
            msg = "value argument must be a string or a 2-tuple of strings."
            raise TypeError(msg)

        self.value = value
        self.case_sensitive = case_sensitive
        self.pattern = (
            value if isinstance(value, tuple) or case_sensitive else _ascii_fold(value)
        )

        self.lparse = (
            self._lparse_range if isinstance(value, tuple) else self._lparse_value
        )

    def _lparse_range(self, source: str, start: int) -> Matches:
        """Parse source when self.value represents a range."""
        # ranges are always case-sensitive
        try:
            src = source[start]
            if self.value[0] <= src <= self.value[1]:
                yield Match([typing.cast(Node, LiteralNode(src, start, 1))], start + 1)
            else:
                raise ParseError(self, start)
        except IndexError as e:
            raise ParseError(self, start) from e

    def _lparse_value(self, source: str, start: int) -> Matches:
        """Parse source when self.value represents a literal."""
        # Enough source must remain for the whole literal.  Slicing would not
        # say so on its own: `source[start:start + n]` silently returns a short
        # string past the end, and for a zero-length literal it returns `''`
        # at *any* start, however far out of range.
        #
        # The guard used to be `start < len(source)`, which also refused a
        # zero-length literal at end of input -- so `""` matched at every
        # offset except `len(source)`, and `"a" ""` could not match `"a"`
        # while `"" "a"` could.  RFC 5234's char-val admits zero characters,
        # and a zero-length match cannot depend on what follows it.
        # See https://github.com/declaresub/abnf/issues/260 .
        if start + len(self.value) > len(source):
            raise ParseError(self, start)
        src = source[start : start + len(self.value)]
        match = src if self.case_sensitive else _ascii_fold(src)
        if match != self.pattern:
            raise ParseError(self, start)
        yield Match(
            [typing.cast(Node, LiteralNode(src, start, len(src)))],
            start + len(src),
        )

    def __str__(self):
        # str(self.value) handles the case value == tuple.
        non_printable_chars = set(map(chr, range(0x00, 0x20)))
        value = tuple(
            rf"\x{ord(x):02x}" if x in non_printable_chars else x for x in self.value
        )

        return (
            f"Literal({value})"
            if isinstance(self.value, tuple)
            else "Literal('%s'%s)"  # noqa: UP031
            % ("".join(value), ", case_sensitive" if self.case_sensitive else "")
        )


class Prose:
    def lparse(self, source: Source, start: int) -> Matches:
        raise ParseError(self, start)


T = typing.TypeVar("T", bound="Rule")


class _FirstMatchAlternation:
    """Backs :attr:`Rule.first_match_alternation` for both class-level and
    per-rule access.

    Read on the class it reports the grammar-wide default; read on a rule it
    reports that rule's alternations.  Written on a rule it flips them.
    (Written in a *class body* it is replaced outright, which is what
    ``Rule.__init_subclass__`` exists to undo.)
    """

    def __get__(self, instance: Rule | None, owner: type[Rule] | None = None) -> bool:
        if instance is None:
            return owner._first_match_default if owner is not None else False
        return instance._get_first_match_alternation()

    def __set__(self, instance: Rule, value: bool) -> None:
        instance._set_first_match_alternation(value)


class _RuleMeta(type):
    """Metaclass for :class:`Rule`, guarding one attribute.

    ``first_match_alternation`` is a descriptor.  Assigning to it *on a class
    object* -- ``MyGrammar.first_match_alternation = True``, rather than in the
    class body -- is an ordinary ``type.__setattr__``, which drops a plain
    ``bool`` into the class dict and shadows the descriptor.  Nothing then
    reads that bool: alternations are built from ``_first_match_default``,
    which is untouched.  So the attribute reported a setting the parser was not
    using, and, worse, the documented per-rule spelling
    (``rule.first_match_alternation = True``) stopped working for that class
    from then on, silently, because it too went to a plain dict rather than
    through the descriptor.

    Refusing the assignment leaves the descriptor in place, so both supported
    spellings keep working and neither can be quietly disabled.
    See https://github.com/declaresub/abnf/issues/258 .
    """

    def __setattr__(cls, name: str, value: typing.Any) -> None:
        if name == "first_match_alternation":
            msg = (
                "first_match_alternation cannot be assigned on a grammar class. "
                "Set it in the class body, before the grammar is loaded:\n\n"
                "    class MyGrammar(Rule):\n"
                "        first_match_alternation = True\n\n"
                "or on one rule: MyGrammar('rulename').first_match_alternation = "
                "True.  Assigning it here would replace the descriptor that "
                "implements both, leaving the flag reading back True while the "
                "parser went on using longest match."
            )
            raise AttributeError(msg)
        super().__setattr__(name, value)


class Rule(metaclass=_RuleMeta):
    """A parser generated from an ABNF rule.

    To create a Rule object, use Rule.create.

    rule = Rule.create('URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]')
    """

    grammar: typing.ClassVar[list[str] | str] = []

    _obj_map: typing.ClassVar[dict[tuple[type[Rule], str], Rule]] = {}

    #: The import list the grammar loader applied, recorded so that a
    #: module's *effective* grammar can be reconstructed as text.  Neither
    #: half says on its own what a module parses: `grammar` is missing the
    #: substitutions, and the loaded rules have the substitutions but no
    #: text.  Empty for a class built any other way.  See
    #: `abnf.grammars.misc._apply_imports` and
    #: `tests/fuzz/effective_grammar.py`.
    _imported_rules: typing.ClassVar[tuple[tuple[str, Rule], ...]] = ()

    def __new__(cls, name: str, definition: Parser | None = None):
        """Overrides super().__new__ to implement a symbol table via object caching."""

        rule = cls.get(name)
        if rule is None:
            rule = super().__new__(cls)
            obj_key = (cls, name.casefold())
            cls._obj_map[obj_key] = rule
        assert rule is not None
        return rule

    def __init__(self, name: str, definition: Parser | None = None):
        try:
            _ = self.name
        except AttributeError:
            self.name = name
        try:
            _ = self._exclude
        except AttributeError:
            # Assign the private slot, not the property: an unset
            # exclusion is the default state and there is nothing for
            # the backend to be told about.
            self._exclude: Rule | None = None

        if definition is not None:
            # when defined-as = '=/', we'll need to overwrite existing definition.
            self.definition = definition

    @property
    def definition(self) -> Parser:
        """Underlying parser combinator for this rule.

        Backed by ``self._definition``.  The property setter forwards
        writes through ``Rule._set_definition_hook`` (when set) so the
        Rust backend can keep its shadow registry of named-rule
        handles in sync with the Python-visible definition graph.
        """

        return self._definition  # type: ignore[attr-defined,no-any-return]

    @definition.setter
    def definition(self, value: Parser) -> None:
        self._definition = value
        hook = getattr(type(self), "_set_definition_hook", None)
        if hook is not None:
            hook(self, value)

    #: Optional hook invoked on every ``rule.definition = ...`` write.
    #: The dispatch shim installs an implementation when the Rust
    #: backend is active; the pure-Python backend leaves it unset.
    _set_definition_hook: typing.ClassVar[
        typing.Callable[[Rule, Parser], None] | None
    ] = None

    @property
    def exclude(self) -> Rule | None:
        """Rule whose complete matches disqualify this rule's matches.

        ``None`` unless set.  Backed by ``self._exclude``; like
        ``definition``, the property setter forwards writes through
        ``Rule._set_exclude_hook`` (when set) so the Rust engine
        applies the exclusion to nested rule references too.

        Assigning here and calling :meth:`exclude_rule` are the same
        operation -- that is the point of the property.  Before it
        existed only the method notified the backend, so
        ``rule.exclude = None`` cleared the exclusion for the
        pure-Python parser while the Rust engine went on applying it.
        """

        return self._exclude

    @exclude.setter
    def exclude(self, value: Rule | None) -> None:
        self._exclude = value
        hook = getattr(type(self), "_set_exclude_hook", None)
        if hook is not None:
            hook(self, value)

    #: Optional hook invoked on every write to ``exclude`` (including
    #: via :meth:`exclude_rule`), so the Rust engine can apply
    #: exclusions to nested rule references.  Unset for the
    #: pure-Python backend, which applies them directly in
    #: ``Rule.lparse``.
    _set_exclude_hook: typing.ClassVar[
        typing.Callable[[Rule, Rule | None], None] | None
    ] = None

    #: Grammar-wide default for alternation semantics, applied to every
    #: ``Alternation`` built for this class's rules -- including ones
    #: nested inside a group or repetition, which is the whole point:
    #: those are unreachable afterwards, since a rule exposes only its
    #: top-level definition.  Written as ``first_match_alternation`` in
    #: a subclass body; ``__init_subclass__`` moves it here so it does
    #: not shadow the property of the same name.
    _first_match_default: typing.ClassVar[bool] = False

    #: Alternations this rule's definition is built from, recorded at
    #: grammar-build time.  ``None`` for a rule built directly from a
    #: parser object, where there is nothing to record.
    _alternations: tuple[Alternation, ...] | None = None

    def __init_subclass__(cls, **kwargs: typing.Any) -> None:
        super().__init_subclass__(**kwargs)
        raw = cls.__dict__.get("first_match_alternation")
        if raw is not None and not isinstance(raw, bool):
            msg = (
                "first_match_alternation must be True or False, not "
                f"{type(raw).__name__}.  A value of any other type is left "
                "shadowing the descriptor that implements the setting, which "
                "would disable it for this grammar without saying so."
            )
            raise TypeError(msg)
        if isinstance(raw, bool):
            cls._first_match_default = raw
            # Restore the inherited property: a plain bool left in the
            # class body would shadow it, so instances of this grammar
            # could neither read nor set the flag per rule.  Deleting via
            # the metaclass removes the class attribute; `del
            # cls.first_match_alternation` would read as an attempt to
            # delete the property itself, which has no deleter.
            type.__delattr__(cls, "first_match_alternation")

    def _alternation_parsers(self) -> tuple[Alternation, ...]:
        """Every ``Alternation`` this rule's own definition is built
        from, outermost first.

        Recorded when the rule is built from ABNF text, because that is
        the only moment the nested ones are in hand: the Rust backend's
        combinators expose no children, so the tree cannot be walked
        afterwards.  Rules constructed directly from a parser fall back
        to the definition itself, which preserves the old behaviour for
        hand-built rules.

        Rules referenced by this one are deliberately not included --
        they are separate rules, with their own setting.
        """

        recorded = getattr(self, "_alternations", None)
        if recorded is not None:
            return recorded
        definition = getattr(self, "_definition", None)
        return (definition,) if isinstance(definition, Alternation) else ()

    def _get_first_match_alternation(self) -> bool:
        """Whether alternation in this rule resolves to the first match.

        ``False`` when the rule contains no alternation at all: there is
        nothing to resolve, so there is nothing to report.
        """

        alternations = self._alternation_parsers()
        return bool(alternations) and all(a.first_match for a in alternations)

    def _set_first_match_alternation(self, value: bool) -> None:
        try:
            _ = self.definition
        except AttributeError as exc:
            msg = f'Undefined rule "{self.name}"'
            raise GrammarError(msg) from exc
        for alternation in self._alternation_parsers():
            alternation.first_match = value
        # A rule with no alternation is not an error -- the same flag set
        # grammar-wide covers plenty of such rules -- so setting it is
        # simply vacuous, and the getter says so.

    if typing.TYPE_CHECKING:
        # Declared as a plain ``bool`` for type checkers.  At runtime it is
        # the descriptor below, which serves both spellings of the same
        # setting -- ``MyGrammar.first_match_alternation = True`` in a class
        # body and ``rule.first_match_alternation = True`` on one rule.  A
        # ``property`` cannot: assigning a bool in a subclass body is an
        # incompatible override, so the documented spelling would not
        # type-check for users.
        first_match_alternation: bool
    else:
        first_match_alternation = _FirstMatchAlternation()

    def exclude_rule(self, rule: Rule) -> None:
        """
        Exclude values which match ``rule``.  For example, suppose we have the
        following grammar::

            foo = %x66.6f.6f
            keyword = foo
            identifier = ALPHA *(ALPHA / DIGIT )

        We don't want to allow a keyword to be an identifier.  To do this::

            Rule('identifier').exclude_rule(Rule('keyword'))

        Then attempting to use "foo" as an identifier would result in a ParseError.

        Equivalent to assigning :attr:`exclude`; assign ``None`` there to
        remove an exclusion.
        """
        self.exclude = rule

    def lparse(self, source: Source, start: int) -> Matches:
        def exclude(match: Match) -> bool:
            if self.exclude is None:
                return False

            try:
                self.exclude.parse_all("".join(item.value for item in match.nodes))
            except ParseError:
                return False
            else:
                return True

        try:
            g = self.definition.lparse(source, start)
        except AttributeError as exc:
            msg = f'Undefined rule "{self.name}"'
            raise GrammarError(msg) from exc

        # Yield matches lazily so callers that only need the first
        # (longest) match don't pay to materialise the entire
        # candidate set.  De-duplicate by end position: two matches
        # ending at the same offset consume the same source span and
        # therefore have the same value, mirroring the original
        # `set(filterfalse(exclude, g))` dedup semantics without the
        # set materialisation.
        seen_starts: set[int] = set()
        yielded = False
        for match in g:
            if match.start in seen_starts:
                continue
            if exclude(match):
                continue
            seen_starts.add(match.start)
            yielded = True
            yield Match(
                [Node(self.name, *match.nodes)],
                match.start,
            )
        if not yielded:
            raise ParseError(self, start) from None

    def parse(self, source: str, start: int) -> tuple[Node, int]:
        """
        :param source: source data
        :type str:
        :param start=0: offset at which to begin parsing.
        :returns: parse tree, new offset at which to continue parsing
        :rtype: Node, int
        :raises ParseError: if source cannot be parsed using rule.
        :raises GrammarError: if rule has no definition.  This usually means that a
            non-terminal in the grammar is not defined or imported.
        :raises ValueError: if start is outside ``0 <= start <= len(source)``.
        """

        # Normalise first: this turns `True` into `1` (the Rust
        # backend already treated it as an index, while here it ended
        # up verbatim in `ParseError.start`) and rejects non-integers
        # with the same message the Rust backend produces.
        start = operator.index(start)

        # Without this check a negative start is a valid Python slice
        # measured from the end of the source, so the parse quietly
        # succeeds at a position the caller never asked for and hands
        # back negative node offsets: `parse("abcdef", -4)` matches
        # "cd".  The Rust backend raises OverflowError on the same
        # input, so the backends disagreed on a case where neither
        # answer was right.
        if not 0 <= start <= len(source):
            msg = (
                f"start must be in 0..{len(source)} for a source of "
                f"length {len(source)}; got {start}."
            )
            raise ValueError(msg)

        # Bind a memo for the duration of this parse.  `reset(token)` restores
        # whatever was bound before, so a nested parse -- `Rule.lparse` runs
        # `exclude.parse_all` on a different source mid-parse -- nests
        # correctly rather than sharing or clobbering this one.  The memo is
        # unreachable once `parse` returns, which is what keeps grammar
        # mutation between parses from ever being observable and keeps
        # retention at zero.
        memo_token = _parse_memo.set((source, {}))
        try:
            return self._parse(source, start)
        finally:
            _parse_memo.reset(memo_token)

    def _parse(self, source: str, start: int) -> tuple[Node, int]:
        g = self.lparse(source, start)
        # `lparse` yields matches longest-first (the upstream
        # combinators sort by `start` descending), so the first
        # value is the longest match.  Pulling only the first lets
        # ambiguous grammars short-circuit the materialisation of
        # losing candidates.  If `g` yields nothing it has already
        # raised `ParseError`; the `next` here therefore never sees
        # `StopIteration` in practice.
        try:
            longest_match = next(g)
        except RecursionError as exc:
            # Deeply-nested input exhausts the Python call stack (the parser is
            # recursive-descent).  Convert to ParseError so the documented
            # exception contract holds instead of leaking RecursionError, and
            # so callers guarding untrusted input with `except ParseError` are
            # not crashed by it.  See GitHub issue #144.  `parse` is the
            # outermost frame, so by the time RecursionError has unwound to
            # here there is stack headroom to raise; and because RecursionError
            # is not a ParseError, the intermediate `except ParseError` handlers
            # in Alternation/Repetition do not swallow it on the way up.
            raise ParseError(self, start) from exc
        return (longest_match.nodes[0], longest_match.start)

    def parse_all(self, source: str) -> Node:
        """
        Parses the source from beginning to end.  If not all of the source is consumed, a
        ParseError is raised.

        :param source: source data
        :type str:
        :param start=0: offset at which to begin parsing.
        :returns: parse tree
        :rtype: Node
        :raises ParseError: if source cannot be parsed using rule.
        :raises GrammarError: if rule has no definition.  This usually means that a
            non-terminal in the grammar is not defined or imported.

        .. note::
            ``source`` is a sequence of Unicode code points, which is what a
            Python ``str`` is; a terminal value in the grammar (``%x41``,
            ``%x10000-1FFFD``) is a code-point value.  To parse wire data,
            decode it with latin-1 -- that maps the 256 byte values onto
            ``U+0000``-``U+00FF`` one to one, so a code point is exactly an
            octet and ``OCTET``/``obs-text`` behave as their RFCs describe::

                rule.parse_all(raw.decode("latin-1"))

            The choice of encoding is a semantic one and belongs to the caller:
            ``b"\\xc3\\xa9"`` is two octets read as latin-1 and one character
            read as UTF-8, and both readings are correct for some input.  See
            the "What abnf parses" page in the documentation.

        .. note::
            Both backends are recursive-descent and both bound how deeply they
            will recurse, reporting input nested past the bound as a ParseError
            rather than crashing.  The pure-Python backend's bound is CPython's
            recursion limit.  The Rust backend budgets native stack instead,
            which puts its ceiling near 180 levels of rule nesting -- lower, but
            the same on every platform and every thread.  (Before that budget
            existed the Rust backend counted levels only, and on a stack too
            small for the count -- Windows, or any thread created with a modest
            ``threading.stack_size`` -- it overflowed and killed the process.)

            To parse input nested more deeply than that, use the pure-Python
            backend, whose bound you can raise: force it with ``ABNF_NO_RUST=1``
            and run the parse on a worker thread with a larger stack and a
            raised recursion limit.  Both levers are needed, as
            ``setrecursionlimit`` alone would overflow the C stack::

                import sys, threading

                def parse_all_deep(rule, source, *, limit=100_000,
                                   stack=256 * 1024 * 1024):
                    threading.stack_size(stack)
                    box = {}
                    def run():
                        sys.setrecursionlimit(limit)  # process-global while running
                        try:
                            box["node"] = rule.parse_all(source)
                        except BaseException as exc:  # re-raised on the caller
                            box["exc"] = exc
                    t = threading.Thread(target=run)
                    t.start()
                    t.join()
                    if "exc" in box:
                        raise box["exc"]
                    return box["node"]
        """

        node, start = self.parse(source, 0)
        if start < len(source):
            raise ParseError(self, start)
        return node

    def __str__(self):
        return f"{self.__class__.__name__}('{self.name}')"

    @classmethod
    def create(cls: type[T], rule_source: Source, start: int = 0) -> T:
        """Creates a Rule object from ABNF source.  A terminating CRLF will be appended to
        rule_source if needed to satisfy the ABNF grammar rule for "rule".

        :param rule_source: the rule source.
        :type str:
        :param start=0: the offset at which to begin parsing rule_source.
        :type int:
        :returns: a Rule object (or subclass of Rule)
        :raises: ParseError
        """

        if rule_source[-2:] != "\r\n":
            rule_source = rule_source + "\r\n"
        parse_tree, start = ABNFGrammarRule("rule").parse(rule_source, start)
        visitor = ABNFGrammarNodeVisitor(cls)
        rule = visitor.visit(parse_tree)
        return rule

    @classmethod
    def load_grammar(cls, grammar: str, strict: bool = True) -> None:
        """Loads grammar and attempts to parse it as a rulelist. If successful,
        cls is populated with the rules in the rulelist.
        When strict = True, line endings following rules are normalized to CRLF to
        satisfy the definition of 'rulelist.  If strict is set to False, the grammar
        is parsed as is.
        """

        assert isinstance(grammar, str)

        if strict:
            # process to ensure that line endings are correct.
            cr = "\r"
            lf = "\n"
            crlf = cr + lf
            src = grammar.rstrip().replace(cr, "").replace(lf, crlf) + crlf
        else:
            src = grammar

        node = ABNFGrammarRule("rulelist").parse_all(src)
        visitor = ABNFGrammarNodeVisitor(rule_cls=cls)
        visitor.visit(node)

    @classmethod
    def from_file(cls, path: str | pathlib.Path) -> None:
        """Loads the contents of path and attempts to parse it as a rulelist. If successful,
        cls is populated with the rules in the rulelist."""

        crlf = "\r\n"
        with (
            open(path, newline=crlf, encoding="ascii")
            if isinstance(path, str)
            else path.open("r", newline=crlf, encoding="ascii")
        ) as f:
            src = f.read()
        cls.load_grammar(src)

    @classmethod
    def get(cls: type[T], name: str, default: T | None = None) -> Rule | None:
        """Retrieves Rule by name.  If a Rule object matching name is found, it is returned.
        Otherwise default is returned, and no Rule object is
        created, as would be the case when invoking Rule(name).
        Note that"""

        _name = name.casefold()
        return cls._obj_map.get((cls, _name), cls._obj_map.get((Rule, _name), default))

    @classmethod
    def rules(cls):
        """Returns a list of all rules created.

        :returns: List
        """

        return [v for k, v in cls._obj_map.items() if k[0] is cls]


#### Node classes ####
# A parser returns a parse tree of Node objects.  Usually one would then walk the node tree
# with a visitor object to do whatever.  A NodeVisitor class, found below, implements
# basic reflective visitor.


class Node:
    """Node objects are used to build parse trees."""

    __slots__ = ("_value", "children", "name")

    def __init__(self, name: str, *children: Node) -> None:
        super().__init__()
        self.name = name
        self.children = list(children)
        self._value = "".join([child.value for child in children])

    @property
    def value(self) -> str:
        """Returns the node value as generated by a parser."""

        return self._value

    def __str__(self) -> str:
        children = ", ".join(x.__str__() for x in self.children)
        return f"Node(name={self.name}, children=[{children}])"

    def __eq__(self, other: typing.Any):
        return (
            self.__class__ == other.__class__
            and self.name == other.name
            and self.children == other.children
        )


class LiteralNode:
    """LiteralNode objects are used to build parse trees."""

    __slots__ = ("length", "name", "offset", "value")

    def __init__(self, value: str, offset: int, length: int):
        super().__init__()
        self.name = "literal"
        self.value = value
        self.offset = offset
        self.length = length

    @property
    def children(self) -> list[Node]:
        """Returns an empty list of children, since LiteralNodes are terminal."""
        return []

    def __str__(self):
        value = self.value.replace("\r", r"\r").replace("\n", r"\n")
        return f'Node(name={self.name}, offset={self.offset}, value="{value}")'

    def __eq__(self, other: typing.Any):
        return (
            self.__class__ == other.__class__
            and self.value == other.value
            and self.offset == other.offset
            and self.length == other.length
        )


_VISIT_PREFIX = "visit_"
_VISIT_NAME_START = len(_VISIT_PREFIX)


class NodeVisitor:
    """An external visitor class."""

    @classmethod
    def _visit_attr_names(cls) -> dict[str, str]:
        """Node name -> attribute name, for every ``visit_*`` on the class.

        `dir()` walks the whole MRO and sorts its result, which is far too
        much work to repeat for every instance: importing the bundled
        grammars alone constructs several hundred visitors.  The answer
        depends only on the class, so compute it once and keep it there.

        Cached in ``cls.__dict__`` rather than read through inheritance, so
        a subclass builds its own table instead of borrowing its parent's.
        """

        # Adding a `visit_*` method to a class after it has been
        # instantiated used to take effect, because the old code rebuilt
        # from `dir(self)` every time.  Keep that working: the summed
        # sizes of the MRO's dicts change whenever a method is added or
        # removed anywhere in the hierarchy, and checking it costs ~240ns
        # against ~3.1us for the scan it guards.  Replacing a method needs
        # no signal at all -- the table maps to attribute *names*, which
        # `getattr` resolves afresh on every instance.
        signature = sum(len(klass.__dict__) for klass in cls.__mro__)
        cached = cls.__dict__.get("_visit_attr_names_cache")
        if cached is not None and cached[0] == signature:
            return cached[1]
        # Casefold the key: `visit` looks up the node name casefolded, so a
        # method named for the rule as the grammar spells it -- `visit_URI`,
        # `visit_IPv4address`, `visit_ATOM_CHAR` -- would otherwise be filed
        # under a key nothing ever asks for, and never run.  Nothing reported
        # it because the miss returns `_skip_visit`, so the node is quietly
        # skipped.  See https://github.com/declaresub/abnf/issues/259 .
        #
        # `dir()` is sorted, so where both spellings exist the lowercase one
        # is assigned last and keeps winning, as it did before.
        table = {
            attr[_VISIT_NAME_START:].casefold(): attr
            for attr in dir(cls)
            if attr.startswith(_VISIT_PREFIX)
        }
        cls._visit_attr_names_cache = (signature, table)
        return table

    def __init__(self):
        cache = {
            name: getattr(self, attr) for name, attr in self._visit_attr_names().items()
        }
        # Instance attributes count too, and not hypothetically:
        # `ABNFGrammarNodeVisitor` assigns `self.visit_char_val` and
        # `self.visit_num_val` before calling up to here, precisely so this
        # picks them up.  `dir(self)` used to cover that; scanning the
        # instance dict covers it for a fraction of the cost, since the
        # dict holds a handful of entries rather than the full MRO.
        for attr in sorted(vars(self)):
            if attr.startswith(_VISIT_PREFIX):
                cache[attr[_VISIT_NAME_START:].casefold()] = getattr(self, attr)
        self._node_method_cache = cache

    def __call__(self, node: Node):
        return self.visit(node)

    def visit(self, node: Node) -> typing.Any:
        """Visit node.  This method invokes the appropriate method for the node type."""
        return self._node_method_cache.get(
            node.name.replace("-", "_").casefold(), self._skip_visit
        )(node)

    @staticmethod
    def _skip_visit(node: Node):
        """Skip node visit."""
        return None


#### Exception classes ####


class ParseError(Exception):
    """Raised in response to errors during parsing.

    ``start`` is the code-point offset at which the parse failed, and
    means the same thing on both backends.

    ``parser`` describes what failed, and is the one attribute whose
    *type* depends on the backend: here it is the parser object, while
    the Rust backend supplies a description string (``"Concatenation"``,
    ``"Literal('a')"``).  An error is constructed on every failed
    alternative, so that backend carries a description prepared once at
    construction rather than a reference to the parser -- which is what
    keeps backtracking cheap.  Treat it as diagnostic output rather than
    something to reach into; ``str(exc)`` and ``exc.start`` behave
    identically either way.
    """

    def __init__(self, parser: Parser, start: int, *args: typing.Any):
        # it turns out that calling super().__init__(*args) is quite slow.  Because
        # ParseError objects are created so often, the slowness adds up.  So we
        # just set self.args directly, which is all that Exception.__init__ does.
        self.args = args
        self.parser = parser
        self.start = start

    def __str__(self):
        return f"{self.parser!s}: {self.start}"


class GrammarError(Exception):
    """Raised in response to errors detected in the grammar."""


class GrammarWarning(UserWarning):
    """Emitted for suspect (but not fatal) conditions detected in a grammar,
    such as a rule that is defined more than once with '='."""


#### Bootstrappery ####
# To get parsing for parser generation started, the ABNF grammar from RFC 5234 and
# RFC 7405, plus the core rules from RFC 5234, are defined ab initio.

for core_rule_def in typing.cast(
    list[tuple[str, Parser]],
    [
        ("ALPHA", Alternation(Literal(("\x41", "\x5a")), Literal(("\x61", "\x7a")))),
        ("BIT", Alternation(Literal("0"), Literal("1"))),
        ("CHAR", Literal(("\x01", "\x7f"))),
        (
            "CTL",
            Alternation(
                Literal(("\x00", "\x1f")), Literal("\x7f", case_sensitive=True)
            ),
        ),
        ("CR", Literal("\x0d", case_sensitive=True)),
        ("CRLF", Concatenation(Rule("CR"), Rule("LF"))),
        ("DIGIT", Literal(("\x30", "\x39"))),
        ("DQUOTE", Literal("\x22", case_sensitive=True)),
        (
            "HEXDIG",
            Alternation(
                Rule("DIGIT"),
                Literal("A"),
                Literal("B"),
                Literal("C"),
                Literal("D"),
                Literal("E"),
                Literal("F"),
            ),
        ),
        ("HTAB", Literal("\x09", case_sensitive=True)),
        ("LF", Literal("\x0a", case_sensitive=True)),
        (
            "LWSP",
            Repetition(
                Repeat(),
                Alternation(Rule("WSP"), Concatenation(Rule("CRLF"), Rule("WSP"))),
            ),
        ),
        ("OCTET", Literal(("\x00", "\xff"))),
        ("SP", Literal("\x20", case_sensitive=True)),
        ("VCHAR", Literal(("\x21", "\x7e"))),
        ("WSP", Alternation(Rule("SP"), Rule("HTAB"))),
    ],
):
    Rule(core_rule_def[0], core_rule_def[1])

#: The RFC 5234 appendix B core rules, which live on the base ``Rule`` class so
#: that every grammar can reference them.  ``Rule.get`` falls back to that
#: registry, so a name here resolves to one object shared by all grammars --
#: which is right for a reference and wrong as somewhere to write.  See
#: ``ABNFGrammarNodeVisitor.visit_rule``, which refuses to define these from a
#: subclass, and https://github.com/declaresub/abnf/issues/256 .
#: Frozen here, immediately after the bootstrap, so it is exactly the core
#: rules and not whatever anyone later adds to the base registry.
CORE_RULE_NAMES = frozenset(rule.name.casefold() for rule in Rule.rules())


class ABNFGrammarRule(Rule):
    """Rules defining ABNF in ABNF."""


for grammar_rule_def in typing.cast(
    list[tuple[str, Parser]],
    [
        (
            "rulelist",
            Repetition(
                Repeat(1),
                Alternation(
                    ABNFGrammarRule("rule"),
                    Concatenation(
                        Repetition(Repeat(), ABNFGrammarRule("c-wsp")),
                        ABNFGrammarRule("c-nl"),
                    ),
                ),
            ),
        ),
        (
            "rule",
            Concatenation(
                ABNFGrammarRule("rulename"),
                ABNFGrammarRule("defined-as"),
                ABNFGrammarRule("elements"),
                ABNFGrammarRule("c-nl"),
            ),
        ),
        (
            "rulename",
            Concatenation(
                Rule("ALPHA"),
                Repetition(
                    Repeat(), Alternation(Rule("ALPHA"), Rule("DIGIT"), Literal("-"))
                ),
            ),
        ),
        (
            "defined-as",
            Concatenation(
                Repetition(Repeat(), ABNFGrammarRule("c-wsp")),
                Alternation(Literal("=/"), Literal("=")),
                Repetition(Repeat(), ABNFGrammarRule("c-wsp")),
            ),
        ),
        (
            "elements",
            Concatenation(
                ABNFGrammarRule("alternation"),
                Repetition(Repeat(), ABNFGrammarRule("c-wsp")),
            ),
        ),
        (
            "c-wsp",
            Alternation(
                Rule("WSP"), Concatenation(ABNFGrammarRule("c-nl"), Rule("WSP"))
            ),
        ),
        ("c-nl", Alternation(ABNFGrammarRule("comment"), Rule("CRLF"))),
        (
            "comment",
            Concatenation(
                Literal(";"),
                Repetition(Repeat(), Alternation(Rule("WSP"), Rule("VCHAR"))),
                Rule("CRLF"),
            ),
        ),
        (
            "alternation",
            Concatenation(
                ABNFGrammarRule("concatenation"),
                Repetition(
                    Repeat(),
                    Concatenation(
                        Repetition(Repeat(), ABNFGrammarRule("c-wsp")),
                        Literal("/"),
                        Repetition(Repeat(), ABNFGrammarRule("c-wsp")),
                        ABNFGrammarRule("concatenation"),
                    ),
                ),
            ),
        ),
        (
            "concatenation",
            Concatenation(
                ABNFGrammarRule("repetition"),
                Repetition(
                    Repeat(),
                    Concatenation(
                        Repetition(Repeat(1), ABNFGrammarRule("c-wsp")),
                        ABNFGrammarRule("repetition"),
                    ),
                ),
            ),
        ),
        (
            "repetition",
            Concatenation(
                Option(ABNFGrammarRule("repeat")), ABNFGrammarRule("element")
            ),
        ),
        (
            "repeat",
            Alternation(
                Concatenation(
                    Repetition(Repeat(0, None), Rule("DIGIT")),
                    Literal("*"),
                    Repetition(Repeat(0, None), Rule("DIGIT")),
                ),
                Repetition(Repeat(1, None), Rule("DIGIT")),
            ),
        ),
        (
            "element",
            Alternation(
                ABNFGrammarRule("rulename"),
                ABNFGrammarRule("group"),
                ABNFGrammarRule("option"),
                ABNFGrammarRule("char-val"),
                ABNFGrammarRule("num-val"),
                ABNFGrammarRule("prose-val"),
            ),
        ),
        (
            "group",
            Concatenation(
                Literal("("),
                Repetition(Repeat(), ABNFGrammarRule("c-wsp")),
                ABNFGrammarRule("alternation"),
                Repetition(Repeat(), ABNFGrammarRule("c-wsp")),
                Literal(")"),
            ),
        ),
        (
            "option",
            Concatenation(
                Literal("["),
                Repetition(Repeat(), ABNFGrammarRule("c-wsp")),
                ABNFGrammarRule("alternation"),
                Repetition(Repeat(), ABNFGrammarRule("c-wsp")),
                Literal("]"),
            ),
        ),
        (
            "num-val",
            Concatenation(
                Literal("%"),
                Alternation(
                    ABNFGrammarRule("bin-val"),
                    ABNFGrammarRule("dec-val"),
                    ABNFGrammarRule("hex-val"),
                ),
            ),
        ),
        (
            "bin-val",
            Concatenation(
                Literal("b"),
                Concatenation(
                    Repetition(Repeat(1), Rule("BIT")),
                    Option(
                        Alternation(
                            Repetition(
                                Repeat(1),
                                Concatenation(
                                    Literal("."), Repetition(Repeat(1), Rule("BIT"))
                                ),
                            ),
                            Concatenation(
                                Literal("-"), Repetition(Repeat(1), Rule("BIT"))
                            ),
                        )
                    ),
                ),
            ),
        ),
        (
            "dec-val",
            Concatenation(
                Literal("d"),
                Concatenation(
                    Repetition(Repeat(1), Rule("DIGIT")),
                    Option(
                        Alternation(
                            Repetition(
                                Repeat(1),
                                Concatenation(
                                    Literal("."), Repetition(Repeat(1), Rule("DIGIT"))
                                ),
                            ),
                            Concatenation(
                                Literal("-"), Repetition(Repeat(1), Rule("DIGIT"))
                            ),
                        )
                    ),
                ),
            ),
        ),
        (
            "hex-val",
            Concatenation(
                Literal("x"),
                Concatenation(
                    Repetition(Repeat(1), Rule("HEXDIG")),
                    Option(
                        Alternation(
                            Repetition(
                                Repeat(1),
                                Concatenation(
                                    Literal("."), Repetition(Repeat(1), Rule("HEXDIG"))
                                ),
                            ),
                            Concatenation(
                                Literal("-"), Repetition(Repeat(1), Rule("HEXDIG"))
                            ),
                        )
                    ),
                ),
            ),
        ),
        (
            "prose-val",
            Concatenation(
                Literal("<"),
                Repetition(
                    Repeat(),
                    Alternation(Literal(("\x20", "\x3d")), Literal(("\x3f", "\x7e"))),
                ),
                Literal(">"),
            ),
        ),
        # definitions from RFC 7405
        (
            "char-val",
            Alternation(
                ABNFGrammarRule("case-insensitive-string"),
                ABNFGrammarRule("case-sensitive-string"),
            ),
        ),
        (
            "case-insensitive-string",
            Concatenation(Option(Literal("%i")), ABNFGrammarRule("quoted-string")),
        ),
        (
            "case-sensitive-string",
            Concatenation(Literal("%s"), ABNFGrammarRule("quoted-string")),
        ),
        (
            "quoted-string",
            Concatenation(
                Rule("DQUOTE"),
                Repetition(
                    Repeat(),
                    Alternation(Literal(("\x20", "\x21")), Literal(("\x23", "\x7e"))),
                ),
                Rule("DQUOTE"),
            ),
        ),
    ],
):
    ABNFGrammarRule(grammar_rule_def[0], grammar_rule_def[1])


def NotNull(x: typing.Any) -> bool:
    return x is not None


class CharValNodeVisitor(NodeVisitor):
    """CharVal node visitor."""

    def visit_char_val(self, node: Node):
        """Visit a char-val node."""
        return self.visit(node.children[0])

    def visit_case_insensitive_string(self, node: Node):
        """Visit a case-insensitive-string node."""
        value: str = next(filter(NotNull, map(self.visit, node.children)))
        return Literal(value, False)

    def visit_case_sensitive_string(self, node: Node):
        """Visit a case-sensitive-string node."""
        value: str = next(filter(NotNull, map(self.visit, node.children)))
        return Literal(value, True)

    @staticmethod
    def visit_quoted_string(node: Node) -> str:
        """Visit a quoted-string node."""
        return node.value[1:-1]


class NumValVisitor(NodeVisitor):
    """Visitor of num-val nodes."""

    def visit_num_val(self, node: Node):
        """Visit a num-val, returning (value, case_sensitive)."""
        return next(filter(NotNull, map(self.visit, node.children)))

    def visit_bin_val(self, node: Node):
        # first child node is marker literal "b"
        return Literal(self._read_value(node.children[1:], "BIT", 2), True)

    def visit_dec_val(self, node: Node):
        # first child node is marker literal "b"
        return Literal(self._read_value(node.children[1:], "DIGIT", 10), True)

    def visit_hex_val(self, node: Node):
        # first child node is marker literal "x"
        return Literal(self._read_value(node.children[1:], "HEXDIG", 16), True)

    def _read_value(
        self, digit_nodes: list[Node], digit_node_name: str, base: int
    ) -> str | tuple[str, str]:
        """Reads the character from the child nodes of the num-val node.
        Returns either a string, or a tuple representing a character range."""

        # type specification needed for mypy to know that value can be either type.
        value: str | tuple[str, str]
        range_op = "-"
        buffer = ""
        iter_nodes = iter(digit_nodes)
        child_node = None
        for child_node in iter_nodes:
            if child_node.name == digit_node_name:
                buffer = buffer + child_node.value
            else:
                break
        assert child_node is not None
        if child_node.value == range_op:
            first_char = self._decode_bytes(buffer, base)
            buffer = ""
            for child_node in iter_nodes:
                buffer = buffer + child_node.value
            last_char = self._decode_bytes(buffer, base)
            value = (first_char, last_char)
        else:
            # either we're done, in the case of a single character, or child_node
            # holds a concatenation operator ".", in which case there are more characters
            # to follow.
            value = self._decode_bytes(buffer, base)
            buffer = ""
            for child_node in iter_nodes:
                if child_node.name == digit_node_name:
                    buffer = buffer + child_node.value
                else:
                    value = value + self._decode_bytes(buffer, base)
                    buffer = ""

            if buffer:
                value = value + self._decode_bytes(buffer, base)
        return value

    @staticmethod
    def _decode_bytes(data: str, base: int) -> str:
        """Decodes num-val byte data. Intended to be private."""
        value = int(data, base=base)
        # `chr` raises ValueError past U+10FFFF, which reaches the caller as a
        # builtin error naming neither the rule nor the grammar.  A num-val
        # outside the code-point space is a grammar error like any other.
        # See https://github.com/declaresub/abnf/issues/261 .
        if value > 0x10FFFF:
            prefix = {2: "%b", 10: "%d", 16: "%x"}.get(base, "%")
            msg = (
                f"{prefix}{data} is not a Unicode code point: values run to "
                "%x10FFFF."
            )
            raise GrammarError(msg)
        return chr(value)


class ABNFGrammarNodeVisitor(NodeVisitor):
    """Visitor for visiting nodes generated from ABNFGrammarRules."""

    def __init__(self, rule_cls: type[Rule], *args: typing.Any, **kwargs: typing.Any):
        self.rule_cls = rule_cls
        #: Alternations built for the rule currently being visited.
        #: Kept because a nested one is otherwise unreachable once the
        #: tree is assembled -- see ``Rule._alternation_parsers``.
        self._alternations: list[Alternation] = []
        self.visit_char_val = CharValNodeVisitor()
        self.visit_num_val = NumValVisitor()
        # superclass init needs to happen here so that it will
        # find these two methods added at runtime.
        super().__init__(*args, **kwargs)

    def visit_alternation(self, node: Node):
        """Creates an Alternation object from alternation node."""
        assert node.name == "alternation"
        args: list[Parser] = list(filter(NotNull, map(self.visit, node.children)))
        if len(args) <= 1:
            # A single alternative is not an alternation; ABNF allows
            # writing one, and it collapses to the element itself.
            return args[0]
        return self._new_alternation(*args)

    def _new_alternation(self, *args: Parser) -> Alternation:
        """Build an `Alternation` with the grammar's semantics, and keep
        hold of it so the rule can reach it later."""
        alternation = Alternation(*args, first_match=self.rule_cls._first_match_default)
        self._alternations.append(alternation)
        return alternation

    def visit_concatenation(self, node: Node):
        """Creates a Concatention object from concatenation node."""
        assert node.name == "concatenation"
        args: list[Parser] = list(filter(NotNull, map(self.visit, node.children)))
        return Concatenation(*args) if len(args) > 1 else args[0]

    @staticmethod
    def visit_defined_as(node: Node):
        """Returns the defined-as operator, ``"="`` or ``"=/"``.

        RFC 5234 section 4 has ``defined-as = *c-wsp ("=" / "=/") *c-wsp``,
        and ``c-wsp`` reaches ``comment`` by way of ``c-nl`` -- so a comment
        may sit on either side of the operator and is part of this node's
        span.  Stripping the span only removes whitespace, which left the
        comment text attached and made the result compare unequal to both
        operators.

        Scanning the span for ``"=/"`` would be no better, since a comment may
        contain that text: ``foo ;see =/ below`` is a plain ``=`` rule.  The
        operator is the one literal among the children, so take it from there.
        """

        return next(
            (child.value for child in node.children if child.name == "literal"),
            node.value.strip(),
        )

    def visit_element(self, node: Node):
        """Creates a parser object from element node."""
        return self.visit(node.children[0])

    def visit_elements(self, node: Node):
        """Creates an Alternation object from elements node."""
        return next(filter(NotNull, map(self.visit, node.children)))

    def visit_group(self, node: Node):
        """Returns an Alternation object from group node."""
        return next(filter(NotNull, map(self.visit, node.children)))

    def visit_option(self, node: Node):
        """Creates an Option object from option node."""
        parser: Parser = next(filter(NotNull, map(self.visit, node.children)))
        return Option(parser)

    def visit_prose_val(self, node: Node):
        """Creates a Prose parser that fails."""
        # check to see if value inside angle brackets could be a rulename. See
        # https://www.rfc-editor.org/rfc/rfc5234.html#section-2.1
        # for the explanation of this bit of hackery.
        try:
            node = ABNFGrammarRule("rulename").parse_all(node.value[1:-1])
        except ParseError:
            return Prose()
        else:
            return self.visit_rulename(node)

    @staticmethod
    def visit_repeat(node: Node):
        """Creates a Repeat object from repeat node."""
        repeat_op = "*"
        min_src = ""
        max_src = ""
        iter_child = iter(node.children)

        child = None
        for child in iter_child:
            if child.name == "DIGIT":
                min_src = min_src + child.value
            else:
                break

        assert child
        if child.value == repeat_op:
            max_src = ""
            for child in iter_child:
                max_src = max_src + child.value
        else:
            max_src = min_src

        return Repeat(
            min=int(min_src, base=10) if min_src else 0,
            max=int(max_src, base=10) if max_src else None,
        )

    def visit_repetition(self, node: Node):
        """Creates a Repetition object from repetition node."""
        if node.children[0].name == "repeat":
            return Repetition(
                self.visit_repeat(node.children[0]),
                self.visit_element(node.children[1]),
            )
        else:
            assert node.children[0].name == "element"
            return self.visit_element(node.children[0])

    def visit_rule(self, node: Node):
        """Visits a rule node, returning a Rule object."""
        rule: Rule
        defined_as: str
        elements: Parser
        # Collect the alternations built while visiting *this* rule; the
        # unpacking below is what drives the lazy map, so the list is
        # empty until then.
        self._alternations = []
        rule, defined_as, elements = filter(NotNull, map(self.visit, node.children))
        # this assertion tells mypy that rule should actually be an object. Without, mypy
        # returns 'error: <nothing> has no attribute "definition"'
        assert rule
        rule_name = next(
            (c.value for c in node.children if c.name == "rulename"), rule.name
        )
        # A core rule lives on the base `Rule` class so that every grammar can
        # reference it, and `Rule.get` falls back there -- so `Rule("DIGIT")`
        # and `MyGrammar("DIGIT")` are one object.  Defining through it would
        # replace the rule for every grammar in the process, including ones
        # this caller never wrote: a grammar defining `DIGIT = %x30-39 / "_"`
        # used to make `rfc3339` accept `2_26` as a year.  Refuse, rather than
        # silently shadow, so the two readings of `DIGIT` can never diverge.
        #
        # Defining one *on the base class itself* is still allowed: it is
        # explicit about its scope, and the redefinition warning below reports
        # it.  See https://github.com/declaresub/abnf/issues/256 .
        if self.rule_cls is not Rule and rule_name.casefold() in CORE_RULE_NAMES:
            msg = (
                f"{rule_name!r} is a core rule from RFC 5234 appendix B, shared by "
                "every grammar, so a grammar cannot define it: the definition would "
                "replace the rule everywhere, not just here.  Core rules are always "
                f"available -- delete this line to use the standard {rule_name}.  To "
                "change it for every grammar deliberately, define it on "
                "abnf.parser.Rule itself."
            )
            raise GrammarError(msg)
        # A plain '=' redefinition silently discards the rule's existing definition
        # (RFC 5234, Section 3.3, allows incremental definition only via '=/').  Because
        # ABNF rule names are case-insensitive, names differing only in case -- e.g.
        # 'Origin' and 'origin' -- resolve to the same rule and collide this way too.
        if defined_as == "=" and getattr(rule, "_definition", None) is not None:
            new_name = rule_name
            existing_name = rule.name
            # This branch is reached only when the names already match under
            # casefold, so an inexact spelling match means they differ only in case.
            detail = (
                f"redefines {existing_name!r}"
                if new_name == existing_name
                else (
                    f"redefines {existing_name!r}, whose name differs only in case "
                    "(ABNF rule names are case-insensitive)"
                )
            )
            warnings.warn(
                f"rule {new_name!r} {detail}; the earlier definition is discarded. "
                "Use '=/' to add an incremental alternative instead of '='.",
                GrammarWarning,
                stacklevel=2,
            )
        if defined_as == "=":
            rule.definition = elements
            rule._alternations = tuple(self._alternations)
        else:
            # '=/' adds to a definition, so there must be one.  Reading it
            # unguarded surfaced as `AttributeError: no attribute
            # '_definition'`, which reads as a library fault rather than as
            # "this grammar is wrong".  RFC 5234 section 3.3 allows
            # incremental alternatives only for an already-defined rule.
            # See https://github.com/declaresub/abnf/issues/261 .
            if getattr(rule, "_definition", None) is None:
                msg = (
                    f"rule {rule_name!r} has no definition to add to: '=/' adds "
                    "an alternative to an existing rule (RFC 5234 section 3.3). "
                    "Use '=' to define it."
                )
                raise GrammarError(msg)
            # '=/' keeps the earlier definition as one arm, so its
            # alternations stay live and stay configurable.
            previous = rule._alternation_parsers()
            rule.definition = self._new_alternation(rule.definition, elements)
            rule._alternations = tuple(previous) + tuple(self._alternations)
        return rule

    def visit_rulelist(self, node: Node):
        """Visits a rulelist node, returning a list of Rule objects."""
        return list(filter(NotNull, map(self.visit, node.children)))

    def visit_rulename(self, node: Node):
        """Visits a rulename node, looks up the Rule object for rulename, and returns it."""
        return self.rule_cls(node.value)
