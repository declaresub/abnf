"""ABNF parser classes."""


#### Parser classes ####

# pylint: disable=too-many-lines

import pathlib
import typing


class Alternation:  # pylint: disable=too-few-public-methods
    """Implements the ABNF alternation operator. -- Alternation(parser1, parser2, ...)
    returns a parser that invokes parser1, parser2, ... in turn and returns the result
    of the first successful parse.."""

    str_template = "Alternation(%s)"

    def __init__(self, *parsers, first_match=False):
        self.parsers = list(parsers)
        self.first_match = first_match
        self.parse = (
            self._parse_first_match if first_match else self._parse_longest_match
        )

    def _parse_first_match(self, source, start):
        """
        :param source: source data
        :type source: str
        :param start: offset at which to begin parsing.
        :type start: int
        :return: parse tree, new offset at which to continue parsing
        :rtype: (Node, int)
        :raises ParseError: if none of the alternation arguments can parse source
        """

        for parser in self.parsers:
            try:
                return parser.parse(source, start)
            except ParseError:
                continue
        raise ParseError(self, start)

    def _parse_longest_match(self, source, start):
        """
        :param source: source data
        :type source: str
        :param start: offset at which to begin parsing.
        :type start: int
        :return: parse tree, new offset at which to continue parsing
        :rtype: (Node, int)
        :raises ParseError: if none of the alternation arguments can parse source
        """

        matches = []
        for parser in self.parsers:
            try:
                matches.append(parser.parse(source, start))
            except ParseError:
                continue

        if matches:  # pylint: disable=no-else-return
            longest_match = matches[0]
            for match in matches[1:]:
                if match[1] > longest_match[1]:
                    longest_match = match
            return longest_match
        else:
            raise ParseError(self, start)

    def __str__(self):
        return self.str_template % ", ".join(map(str, self.parsers))


class Concatenation:  # pylint: disable=too-few-public-methods
    """Implements the ABNF concatention operation. Concatention(parser1, parser2, ...)
    returns a parser that invokes parser1, parser2, ... in turn and returns a list of Nodes
    if every parser succeeds.
    """

    str_template = "Concatenation(%s)"

    def __init__(self, *parsers):
        self.parsers = parsers

    def parse(self, source, start):
        """
        :param source: source data
        :type str:
        :param start: offset at which to begin parsing.
        :returns: a List of Node objects, new offset at which to continue parsing
        :rtype: List, int
        :raises ParseError: if one of the concatenation arguments fails to parse source
        """
        nodes = []
        new_start = start
        for parser in self.parsers:
            try:
                node, new_start = parser.parse(source, new_start)
            except ParseError as e:
                raise ParseError(self, start) from e
            else:
                nodes.append(node)

        return flatten(nodes), new_start

    def __str__(self):
        return self.str_template % ", ".join(map(str, self.parsers))


class Literal:  # pylint: disable=too-few-public-methods
    """Represents a terminal literal value."""

    def __init__(self, value, case_sensitive=False):
        """
        value is either a string to be matched, or a two-element tuple representing an
        inclusive range; e.g. ('a', 'z') matches all letters a-z.
        """

        if not (
            isinstance(value, str)
            or (
                isinstance(value, tuple)
                and len(value) == 2
                and isinstance(value[0], str)
                and isinstance(value[1], str)
            )
        ):
            raise TypeError("value argument must be a string or a 2-tuple of strings.")

        self.value = value
        self.case_sensitive = case_sensitive
        self.pattern = (
            value if isinstance(value, tuple) or case_sensitive else value.casefold()
        )

        self.parse = self._parse_range if isinstance(value, tuple) else self._parse

    def _parse_range(self, source, start):
        """Parse source when self.value represents a range."""
        # ranges are always case-sensitive
        try:
            if (  # pylint: disable=no-else-return
                self.value[0] <= source[start] and source[start] <= self.value[1]
            ):
                return LiteralNode(source[start], start, 1), start + 1
            else:
                raise ParseError(self, start)
        except IndexError as e:
            raise ParseError(self, start) from e

    def _parse(self, source, start):
        """Parse source when self.value represents a literal."""
        # we check position to ensure that the case pattern = '' and start >= len(source)
        # is handled correctly.
        if start < len(source):  # pylint: disable=no-else-return
            src = source[start : start + len(self.value)]
            match = src if self.case_sensitive else src.casefold()
            if match == self.pattern:  # pylint: disable=no-else-return
                return LiteralNode(src, start, len(src)), start + len(src)
            else:
                raise ParseError(self, start)
        else:
            raise ParseError(self, start)

    def __str__(self):
        # str(self.value) handles the case value == tuple.
        non_printable_chars = set(map(chr, range(0x00, 0x20)))
        value = tuple(
            [r"\x%02x" % ord(x) if x in non_printable_chars else x for x in self.value]
        )

        return (
            "Literal(%s)" % str(value)
            if isinstance(self.value, tuple)
            else "Literal('%s'%s)"
            % ("".join(value), ", case_sensitive" if self.case_sensitive else "")
        )


class Option:  # pylint: disable=too-few-public-methods
    """Implements the ABNF Option operation."""

    str_template = "Option(%s)"

    def __init__(self, alternation):
        self.alternation = alternation

    def parse(self, source, start):
        """
        :param source: source data
        :type str:
        :param start: offset at which to begin parsing.
        :returns: parse tree, new offset at which to continue parsing
        :rtype: Node, int
        :raises ParseError:
        """
        try:
            node, new_start = self.alternation.parse(source, start)
        except ParseError:
            node, new_start = ([], start)

        return node, new_start

    def __str__(self):
        return self.str_template % str(self.alternation)


class Repeat:  # pylint: disable=too-few-public-methods
    """Implements the ABNF Repeat operator for Repetition."""

    def __init__(self, min=0, max=None):  # pylint: disable=redefined-builtin
        self.min = min
        self.max = max

    def __str__(self):
        return "Repeat(%s, %s)" % (self.min, self.max if max is not None else "None")


class Repetition:  # pylint: disable=too-few-public-methods
    """Implements the ABNF Repetition operation."""

    def __init__(self, repeat, element):
        self.repeat = repeat
        self.element = element

    def parse(self, source, start):
        """
        :param source: source data
        :type str:
        :param start: offset at which to begin parsing.
        :returns: parse tree, new offset at which to continue parsing
        :rtype: Node, int
        :raises ParseError:
        """
        new_start = start
        nodes = []
        end_of_source = len(source)
        while new_start < end_of_source:
            try:
                node, new_start = self.element.parse(source, new_start)
            except ParseError:
                break
            else:
                nodes.append(node)
                if self.repeat.max and len(nodes) == self.repeat.max:
                    break

        # should write something explicit about behavior when self.element.parse returns
        # a zero-length match  -- [].
        if len(nodes) >= self.repeat.min:  # pylint: disable=no-else-return
            return flatten(nodes), new_start
        else:
            raise ParseError(self, start)

    def __str__(self):
        return "Repetition(%s, %s)" % (self.repeat, self.element)


class Rule:
    """A parser generated from an ABNF rule.

    To create a Rule object, use Rule.create.

    rule = Rule.create('URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]')
    """

    first_match_alternation = False

    _obj_map = {}  # type: dict

    def __new__(cls, name, definition=None):  # pylint: disable=unused-argument
        """Overrides super().__new__ to implement a symbol table via object caching.
        """

        return cls.get(name, super(Rule, cls).__new__(cls))

    def __init__(self, name, definition=None):
        obj_key = (self.__class__, name.casefold())
        if obj_key not in self._obj_map:
            self._obj_map[obj_key] = self
            self.name = name
        if definition is not None:
            # when defined-as = '=/', we'll need to overwrite existing definition.
            self.definition = definition
        self.exclude = None

    def exclude_rule(self, rule: "Rule") -> None:
        """
        Exclude values which match rule.  For example, suppose we have the following
        grammar.

        foo = %x66.6f.6f
        keyword = foo
        identifier = ALPHA *(ALPHA / DIGIT )

        We don't want to allow a keyword to be an identifier.  To do this,
        Rule('identifier').exclude_rule(Rule('keyword'))

        Then attempting to use "foo" as a keyword would result in a ParseError.
        """
        self.exclude = rule

    def parse(self, source, start=0):
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
        try:
            try:
                node, new_start = self.definition.parse(source, start)
            except AttributeError as e:
                raise GrammarError('Undefined rule "%s".' % self.name) from e
            nodes = flatten(node)
            if self.exclude is not None:
                try:
                    self.exclude.parse_all("".join(node.value for node in nodes))
                except ParseError:
                    pass
                else:
                    raise ParseError(self.exclude, start)
        except ParseError as e:
            raise ParseError(self, start) from e
        else:
            rule_node = Node(self.name, *nodes)
            return rule_node, new_start

    def parse_all(self, source):
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
        return "%s('%s')" % (self.__class__.__name__, self.name)

    @classmethod
    def create(cls, rule_source, start=0):
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
        return visitor.visit(parse_tree)

    @classmethod
    def from_file(cls, path: typing.Union[str, pathlib.Path]) -> None:
        """Loads the contents of path and attempts to parse it as a rulelist. If successful,
        cls is populated with the rules in the rulelist."""

        crlf = "\r\n"
        with (
            open(path, "r", newline=crlf)
            if isinstance(path, str)
            else path.open("r", newline=crlf)
        ) as f:  # pylint: disable=invalid-name
            src = f.read()

        node = ABNFGrammarRule("rulelist").parse_all(src)
        visitor = ABNFGrammarNodeVisitor(rule_cls=cls)
        visitor.visit(node)

    @classmethod
    def get(cls, name, default=None):
        """Retrieves Rule by name.  If a Rule object matching name is found, it is returned.
        Otherwise default is returned, and no Rule object is
        created, as would be the case when invoking Rule(name)."""

        _name = name.casefold()
        return cls._obj_map.get((cls, _name), cls._obj_map.get((Rule, _name), default))

    @classmethod
    def rules(cls):
        """Returns a list of all rules created.

        :returns: List
        """

        return [v for k, v in cls._obj_map.items() if k[0] == cls]


#### Node classes ####
# A parser returns a parse tree of Node objects.  Usually one would then walk the node tree
# with a visitor object to do whatever.  A NodeVisitor class, found below, implements
# basic reflective visitor.


class Node:  # pylint: disable=too-few-public-methods
    """Node objects are used to build parse trees."""

    def __init__(self, name: str, *children: "Node") -> None:
        super(Node, self).__init__()
        self.name = name
        self.children = children

    @property
    def value(self) -> str:
        """Returns the node value as generated by a parser."""

        return "".join(child.value for child in self.children)

    def __str__(self) -> str:
        return "Node(name=%s, children=[%s])" % (
            self.name,
            ", ".join(x.__str__() for x in self.children),
        )

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.__dict__ == other.__dict__


class LiteralNode:  # pylint: disable=too-few-public-methods
    """LiteralNode objects are used to build parse trees."""

    def __init__(self, value, offset, length):
        super(LiteralNode, self).__init__()
        self.name = "literal"
        self.value = value
        self.offset = offset
        self.length = length

    @property
    def children(self):
        """Returns an empty list of children, since LiteralNodes are terminal."""
        return []

    def __str__(self):
        return 'Node(name=%s, offset=%s, value="%s")' % (
            self.name,
            self.offset,
            self.value.replace("\r", r"\r").replace("\n", r"\n"),
        )

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.__dict__ == other.__dict__


class NodeVisitor:  # pylint: disable=too-few-public-methods
    """An external visitor class."""

    def __init__(self):
        self._node_method_cache = {}

    def __call__(self, node):
        return self.visit(node)

    def visit(self, node):
        """Visit node.  This method invokes the appropriate method for the node type."""
        return self._node_method(node)(node)

    @staticmethod
    def _dont_visit(node):  # pylint: disable=unused-argument
        """ Skip node visit."""
        return None

    def _node_method(self, node):
        """Looks up method for node using node.name."""
        node_name = node.name.casefold()
        try:
            node_method = self._node_method_cache[node_name]
        except KeyError:
            try:
                node_method = getattr(self, "visit_%s" % node_name.replace("-", "_"))
            except AttributeError:
                node_method = self._dont_visit

            self._node_method_cache[node_name] = node_method

        return node_method


#### Exception classes ####


class ParseError(Exception):
    """Raised in response to errors during parsing."""

    def __init__(
        self, parser, start: int, *args
    ):  # pylint: disable=super-init-not-called
        if parser is None:
            raise ValueError("parser must not be None")
        if start is None:
            raise ValueError("start must not be None")

        # it turns out that calling super().__init__(*args) is quite slow.  Because
        # ParseError objects are created so often, the slowness adds up.  So we
        # just set self.args directly, which is all that Exception.__init__ does.
        self.args = args
        self.parser = parser
        self.start = start

    def __str__(self):
        return "%s: %s" % (str(self.parser), self.start)


class GrammarError(Exception):
    """Raised in response to errors detected in the grammar."""


#### Other code ####


def flatten(*L):
    """Takes an item, or a list of items, of which some items may be lists, and returns a list; e.g.
    flatten(1) returns [1]
    flatten([1] returns [1]
    flatten([1, 2, 3], 4, [5]) returns [1, 2, 3, 4, 5].
    """

    flat_list = []
    for item in L:
        if isinstance(item, list):
            flat_list.extend(flatten(*item))
        else:
            flat_list.append(item)
    return flat_list


#### Bootstrappery ####
# To get parsing for parser generation started, the ABNF grammar from RFC 5234 and
# RFC 7405, plus the core rules from RFC 5234, are defined ab initio.

for core_rule_def in [
    ("ALPHA", Alternation(Literal(("\x41", "\x5A")), Literal(("\x61", "\x7A")))),
    ("BIT", Alternation(Literal("0"), Literal("1"))),
    ("CHAR", Literal(("\x01", "\x7F"))),
    (
        "CTL",
        Alternation(Literal(("\x00", "\x1F")), Literal("\x7F", case_sensitive=True)),
    ),
    ("CR", Literal("\x0D", case_sensitive=True)),
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
    ("LF", Literal("\x0A", case_sensitive=True)),
    (
        "LWSP",
        Repetition(
            Repeat(), Alternation(Rule("WSP"), Concatenation(Rule("CRLF"), Rule("WSP")))
        ),
    ),
    ("OCTET", Literal(("\x00", "\xFF"))),
    ("SP", Literal("\x20", case_sensitive=True)),
    ("VCHAR", Literal(("\x21", "\x7E"))),
    ("WSP", Alternation(Rule("SP"), Rule("HTAB"))),
]:
    Rule(*core_rule_def)


class ABNFGrammarRule(Rule):
    """Rules defining ABNF in ABNF. """


for grammar_rule_def in [
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
        Alternation(Rule("WSP"), Concatenation(ABNFGrammarRule("c-nl"), Rule("WSP"))),
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
        Concatenation(Option(ABNFGrammarRule("repeat")), ABNFGrammarRule("element")),
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
                        Concatenation(Literal("-"), Repetition(Repeat(1), Rule("BIT"))),
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
                Alternation(Literal(("\x20", "\x3D")), Literal(("\x3F", "\x7E"))),
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
                Alternation(Literal(("\x20", "\x21")), Literal(("\x23", "\x7E"))),
            ),
            Rule("DQUOTE"),
        ),
    ),
]:
    ABNFGrammarRule(*grammar_rule_def)


class CharValNodeVisitor(NodeVisitor):
    """CharVal node visitor."""

    def visit_char_val(self, node):
        """Visit a char-val node."""
        return self.visit(node.children[0])

    def visit_case_insensitive_string(self, node):
        """Visit a case-insensitive-string node."""
        value = next(filter(None, map(self.visit, node.children)))
        return Literal(value, False)

    def visit_case_sensitive_string(self, node):
        """Visit a case-sensitive-string node."""
        value = next(filter(None, map(self.visit, node.children)))
        return Literal(value, True)

    @staticmethod
    def visit_quoted_string(node):
        """Visit a quoted-string node."""
        return node.value[1:-1]


class NumValVisitor(NodeVisitor):
    """Visitor of num-val nodes."""

    def visit_num_val(self, node):  # pylint:disable=missing-function-docstring
        """Visit a num-val, returning (value, case_sensitive)."""
        return next(filter(None, map(self.visit, node.children)))

    def visit_bin_val(self, node):  # pylint:disable=missing-function-docstring
        # first child node is marker literal "b"
        return Literal(self._read_value(node.children[1:], "BIT", 2), True)

    def visit_dec_val(self, node):  # pylint:disable=missing-function-docstring
        # first child node is marker literal "b"
        return Literal(self._read_value(node.children[1:], "DIGIT", 10), True)

    def visit_hex_val(self, node):  # pylint:disable=missing-function-docstring
        # first child node is marker literal "x"
        return Literal(self._read_value(node.children[1:], "HEXDIG", 16), True)

    def _read_value(self, digit_nodes, digit_node_name, base):
        """Reads the character from the child nodes of the num-val node.
        Returns either a string, or a tuple representing a character range."""

        range_op = "-"
        buffer = ""
        iter_nodes = iter(digit_nodes)
        child_node = None
        for child_node in iter_nodes:
            if child_node.name == digit_node_name:
                buffer = buffer + child_node.value
            else:
                break

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
    def _decode_bytes(data, base):
        """Decodes num-val byte data. Intended to be private."""
        return chr(int(data, base=base))


class ABNFGrammarNodeVisitor(NodeVisitor):
    """Visitor for visiting nodes generated from ABNFGrammarRules.  """

    def __init__(self, rule_cls, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rule_cls = rule_cls
        self.visit_char_val = CharValNodeVisitor()
        self.visit_num_val = NumValVisitor()

    def visit_alternation(self, node):
        """Creates an Alternation object from alternation node."""
        assert node.name == "alternation"
        args = list(filter(None, map(self.visit, node.children)))
        return (
            Alternation(*args, first_match=self.rule_cls.first_match_alternation)
            if len(args) > 1
            else args[0]
        )

    def visit_concatenation(self, node):
        """Creates a Concatention object from concatenation node."""
        assert node.name == "concatenation"
        args = list(filter(None, map(self.visit, node.children)))
        return Concatenation(*args) if len(args) > 1 else args[0]

    @staticmethod
    def visit_defined_as(node):
        """Returns defined-as operator."""
        return node.value.strip()

    def visit_element(self, node):
        """Creates a parser object from element node."""
        return self.visit(node.children[0])

    def visit_elements(self, node):
        """Creates an Alternation object from elements node."""
        return next(filter(None, map(self.visit, node.children)))

    def visit_group(self, node):
        """Returns an Alternation object from group node."""
        return next(filter(None, map(self.visit, node.children)))

    def visit_option(self, node):
        """Creates an Option object from option node."""
        parser = next(filter(None, map(self.visit, node.children)))
        return Option(parser)

    @staticmethod
    def visit_prose_val(node):
        """Raises a GrammarError if a prose-val is encountered."""
        raise GrammarError("Grammar contains a prose-val.")

    @staticmethod
    def visit_repeat(node):
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

    def visit_repetition(self, node):
        """Creates a Repetition object from repetition node."""
        if node.children[0].name == "repeat":  # pylint: disable=no-else-return
            return Repetition(
                self.visit_repeat(node.children[0]),
                self.visit_element(node.children[1]),
            )
        else:
            assert node.children[0].name == "element"
            return self.visit_element(node.children[0])

    def visit_rule(self, node):
        """Visits a rule node, returning a Rule object."""
        rule, defined_as, elements = filter(None, map(self.visit, node.children))
        rule.definition = (
            elements if defined_as == "=" else Alternation(rule.definition, elements)
        )
        return rule

    def visit_rulelist(self, node):
        """Visits a rulelist node, returning a list of Rule objects."""
        return list(filter(None, map(self.visit, node.children)))

    def visit_rulename(self, node):
        """Visits a rulename node, looks up the Rule object for rulename, and returns it."""
        return self.rule_cls(node.value)
