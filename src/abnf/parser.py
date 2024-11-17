from __future__ import annotations

import pathlib
import typing
from collections import OrderedDict
from collections.abc import Generator
from itertools import filterfalse
from weakref import WeakSet

from .typing import Protocol, runtime_checkable

Source = str
Nodes = list["Node"]


class Match:
    def __init__(self, nodes: Nodes, start: int):
        self.nodes = nodes
        self.start = start

    def __hash__(self) -> int:
        value = "".join(n.value for n in self.nodes)
        return hash((value, self.start))

    def __str__(self):
        return (
            f'Match(value={"".join(n.value for n in self.nodes)}, start={self.start})'
        )

    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, self.__class__) and hash(self) == hash(__o)


MatchSet = set[Match]
Matches = typing.Iterator[Match]


def sorted_by_longest_match(matches: typing.Iterable[Match]) -> list[Match]:
    return sorted(matches, key=lambda item: item.start, reverse=True)


def next_longest(matches: MatchSet) -> Generator[Match, None, None]:
    yield from sorted_by_longest_match(list(matches))


@runtime_checkable
class Parser(Protocol):
    # def parse(
    #    self, source: str, start: int
    # ) -> tuple[Nodes, int]:  # pragma: no cover
    #   ...
    def lparse(self, source: Source, start: int) -> Matches: ...  # pragma: no cover


ParseCacheKey = tuple[str, int]
ParseCacheValue = typing.Union[MatchSet, "ParseError"]


class ParseCache(typing.MutableMapping[ParseCacheKey, ParseCacheValue]):
    max_cache_size: int | None = None
    objects: WeakSet[ParseCache] = WeakSet()

    def __new__(cls, max_size: int | None = None):
        obj = super().__new__(cls)
        cls.objects.add(obj)
        return obj

    def __init__(self, max_size: typing.Union[int, None] = None):
        self.dict: OrderedDict[ParseCacheKey, MatchSet | ParseError] = OrderedDict()
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
        match_found = False
        for parser in self.parsers:
            try:
                # note that parser,lparse could return an empty list, say from
                # something like *"a" .
                for item in parser.lparse(source, start):
                    match_found = True
                    yield (item)
            except ParseError:
                continue
            if self.first_match:
                return
        if not match_found:
            raise ParseError(self, start)

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
        yield from sorted_by_longest_match(match_list)

    def __str__(self):
        return self.str_template % ", ".join(map(str, self.parsers))


class Repeat:
    """Implements the ABNF Repeat operator for Repetition."""

    def __init__(self, min: int = 0, max: typing.Union[int, None] = None):
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
        self.lparse_cache = ParseCache()

    def lparse(self, source: Source, start: int) -> Matches:
        cache_key = (source, start)
        try:
            cached_matchset = self.lparse_cache[cache_key]
        except KeyError:
            pass
        else:
            if isinstance(cached_matchset, ParseError):
                raise cached_matchset
            yield from next_longest(cached_matchset)
            return

        if self.repeat.min == 0:
            match_set: MatchSet = {Match([], start)}
        else:
            concat_parser = Concatenation(*([self.element] * self.repeat.min))
            try:
                # if this raises a ParseError, then the minimum match was not reached.
                match_set = set(concat_parser.lparse(source, start))
            except ParseError as exc:
                self.lparse_cache[cache_key] = exc
                raise

        last_match_set = set(match_set)
        match_count = self.repeat.min

        while True:
            if self.repeat.max is not None and match_count == self.repeat.max:
                break

            new_match_set: MatchSet = set()
            for match in last_match_set:
                g = self.element.lparse(source, match.start)
                try:  # noqa: SIM105
                    new_match_set.update(
                        [Match(match.nodes + m.nodes, m.start) for m in g]
                    )
                except ParseError:
                    pass

            if not new_match_set <= match_set:
                match_count = match_count + 1
                match_set = match_set | new_match_set
                last_match_set = new_match_set
            else:
                break

        self.lparse_cache[cache_key] = match_set
        yield from next_longest(match_set)

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
        value: typing.Union[str, tuple[str, str]],
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
            value if isinstance(value, tuple) or case_sensitive else value.casefold()
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
        # we check position to ensure that the case pattern = '' and start >= len(source)
        # is handled correctly.
        if start < len(source):
            src = source[start : start + len(self.value)]
            match = src if self.case_sensitive else src.casefold()
            if match == self.pattern:
                yield Match(
                    [typing.cast(Node, LiteralNode(src, start, len(src)))],
                    start + len(src),
                )
            else:
                raise ParseError(self, start)
        else:
            raise ParseError(self, start)

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


class Rule:
    """A parser generated from an ABNF rule.

    To create a Rule object, use Rule.create.

    rule = Rule.create('URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]')
    """

    grammar: typing.ClassVar[list[str] | str] = []

    _obj_map: typing.ClassVar[dict[tuple[type[Rule], str], Rule]] = {}

    def __new__(cls, name: str, definition: typing.Union[Parser, None] = None):
        """Overrides super().__new__ to implement a symbol table via object caching."""

        rule = cls.get(name)
        if rule is None:
            rule = super().__new__(cls)
            obj_key = (cls, name.casefold())
            cls._obj_map[obj_key] = rule
        assert rule is not None
        return rule

    def __init__(self, name: str, definition: typing.Union[Parser, None] = None):
        try:
            _ = self.name
        except AttributeError:
            self.name = name
        try:
            _ = self.exclude
        except AttributeError:
            self.exclude: typing.Optional[Rule] = None

        if definition is not None:
            # when defined-as = '=/', we'll need to overwrite existing definition.
            self.definition = definition

    @property
    def first_match_alternation(self) -> bool:
        try:
            definition = self.definition
        except AttributeError:
            return False
        else:
            return isinstance(definition, Alternation) and definition.first_match

    @first_match_alternation.setter
    def first_match_alternation(self, value: bool):
        try:
            definition = self.definition
        except AttributeError as exc:
            msg = f'Undefined rule "{self.name}"'
            raise GrammarError(msg) from exc
        else:
            if isinstance(definition, Alternation):
                definition.first_match = value
            else:
                # skip.  Or should some exception be raised?
                pass

    def exclude_rule(self, rule: Rule) -> None:
        """
        Exclude values which match rule.  For example, suppose we have the following
        grammar.
        foo = %x66.6f.6f
        keyword = foo
        identifier = ALPHA *(ALPHA / DIGIT )

        We don't want to allow a keyword to be an identifier.  To do this,
        Rule('identifier').exclude_rule(Rule('keyword'))

        Then attempting to use "foo" as an identifier would result in a ParseError.
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

        matches = set(filterfalse(exclude, g))
        if matches:
            yield from [
                Match([Node(self.name, *match.nodes)], match.start) for match in matches
            ]
        else:
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
        """

        g = self.lparse(source, start)
        matches = set(g)
        assert matches
        # we return the longest match.  It is possible that there is more than one
        # match of maximal length.  Call lparse to see all amatches
        longest_match = next(next_longest(matches))
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
    def from_file(cls, path: typing.Union[str, pathlib.Path]) -> None:
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
    def get(
        cls: type[T], name: str, default: typing.Optional[T] = None
    ) -> typing.Optional[Rule]:
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

    __slots__ = ("name", "children", "_value")

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
        return "Node(name={}, children=[{}])".format(
            self.name,
            ", ".join(x.__str__() for x in self.children),
        )

    def __eq__(self, other: typing.Any):
        return (
            self.__class__ == other.__class__
            and self.name == other.name
            and self.children == other.children
        )


class LiteralNode:
    """LiteralNode objects are used to build parse trees."""

    __slots__ = ("name", "value", "offset", "length")

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
        return 'Node(name={}, offset={}, value="{}")'.format(
            self.name,
            self.offset,
            self.value.replace("\r", r"\r").replace("\n", r"\n"),
        )

    def __eq__(self, other: typing.Any):
        return (
            self.__class__ == other.__class__
            and self.value == other.value
            and self.offset == other.offset
            and self.length == other.length
        )


class NodeVisitor:
    """An external visitor class."""

    def __init__(self):
        self._node_method_cache = {}
        method_prefix = "visit_"
        name_start = len(method_prefix)
        self._node_method_cache = {
            attr[name_start:]: getattr(self, attr)
            for attr in dir(self)
            if attr.startswith(method_prefix)
        }

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
    """Raised in response to errors during parsing."""

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
    ) -> typing.Union[str, tuple[str, str]]:
        """Reads the character from the child nodes of the num-val node.
        Returns either a string, or a tuple representing a character range."""

        # type specification needed for mypy to know that value can be either type.
        value: typing.Union[str, tuple[str, str]]
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
        return chr(int(data, base=base))


class ABNFGrammarNodeVisitor(NodeVisitor):
    """Visitor for visiting nodes generated from ABNFGrammarRules."""

    def __init__(self, rule_cls: type[Rule], *args: typing.Any, **kwargs: typing.Any):
        self.rule_cls = rule_cls
        self.visit_char_val = CharValNodeVisitor()
        self.visit_num_val = NumValVisitor()
        # superclass init needs to happen here so that it will
        # find these two methods added at runtime.
        super().__init__(*args, **kwargs)

    def visit_alternation(self, node: Node):
        """Creates an Alternation object from alternation node."""
        assert node.name == "alternation"
        args: list[Parser] = list(filter(NotNull, map(self.visit, node.children)))
        return Alternation(*args) if len(args) > 1 else args[0]

    def visit_concatenation(self, node: Node):
        """Creates a Concatention object from concatenation node."""
        assert node.name == "concatenation"
        args: list[Parser] = list(filter(NotNull, map(self.visit, node.children)))
        return Concatenation(*args) if len(args) > 1 else args[0]

    @staticmethod
    def visit_defined_as(node: Node):
        """Returns defined-as operator."""
        return node.value.strip()

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
        rule, defined_as, elements = filter(NotNull, map(self.visit, node.children))
        # this assertion tells mypy that rule should actually be an object. Without, mypy
        # returns 'error: <nothing> has no attribute "definition"'
        assert rule
        rule.definition = (
            elements if defined_as == "=" else Alternation(rule.definition, elements)
        )
        return rule

    def visit_rulelist(self, node: Node):
        """Visits a rulelist node, returning a list of Rule objects."""
        return list(filter(NotNull, map(self.visit, node.children)))

    def visit_rulename(self, node: Node):
        """Visits a rulename node, looks up the Rule object for rulename, and returns it."""
        return self.rule_cls(node.value)
