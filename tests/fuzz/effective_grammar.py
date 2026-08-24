"""Reconstruct a grammar module's *effective* grammar as self-contained ABNF.

A module's rules come from two places: the ABNF in ``Rule.grammar``, and an
import list that substitutes other modules' rules over the top of it.  Neither
says on its own what the module parses -- the loaded ``Rule`` objects carry no
text, and ``Rule.grammar`` is missing the substitutions.  This joins them.

The point is to end up with ABNF *text*, which an outside tool can read.
``gen_corpus.py`` walks the built combinators instead, so it inherits whatever
the loader produced: if a rule was built wrong, the generator generates from
the wrong rule and the parser accepts everything it emits.  Generator and
parser agree by construction, and nothing between them is visible.  Text that
abnfgen parses independently does not have that problem, which is the whole
reason for the detour (issue #251).

Four things make this more than a concatenation.

**Rules are scoped per class, and the scopes collide.**  ``rfc6265`` has a
helper class whose ``domain-value`` is imported as ``subdomain``, while the
main class has a *different* ``subdomain``.  Flattening by name turns that into
``subdomain = subdomain / ...``, which is not the grammar -- so keys here are
``(module, name)`` pairs and a name gets mangled when two keys want it.

**Imports may rename.**  ``rfc7230`` imports RFC 3986's ``host`` as
``uri-host``, so a definition is written under a name its body never had.

**Imports are transitive, and they win.**  A rule pulled from another module
resolves *its* references in that module's namespace, and those may be
imported in turn.  An import is applied after the grammar text, so it beats
the module's own definition of the same name -- including the prose
placeholder it exists to replace.

**Prose that names a rule is a reference.**  ``<subdomain>`` is not prose to
the loader: ``visit_prose_val`` reparses the contents, and a bare rulename
becomes a reference (``_parser_python.py``).  Only prose that is not a
rulename, like ``<any CHAR except CTLs>``, stays prose.

Rulenames are case-insensitive (RFC 5234 section 2.1), so keys are folded.
"""

from __future__ import annotations

import re

from abnf.parser import Rule

#: RFC 5234 appendix B core rules.  abnfgen preloads these and abnf defines
#: them on the base Rule class, so neither side needs them written out.
CORE_RULES = frozenset(
    {
        "ALPHA",
        "BIT",
        "CHAR",
        "CR",
        "CRLF",
        "CTL",
        "DIGIT",
        "DQUOTE",
        "HEXDIG",
        "HTAB",
        "LF",
        "LWSP",
        "OCTET",
        "SP",
        "VCHAR",
        "WSP",
    }
)
_CORE_FOLDED = frozenset(name.casefold() for name in CORE_RULES)

#: A rulename, per RFC 5234: ALPHA *(ALPHA / DIGIT / "-").
_RULENAME = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
_RULENAME_ONLY = re.compile(r"\A[A-Za-z][A-Za-z0-9-]*\Z")

#: A rule's definition begins at column 0; continuation lines are indented.
_DEFINITION_START = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)[ \t]*(=/?)", re.MULTILINE)

#: Numeric terminals (%x41, %d97-122, %b1010.1011) and RFC 7405's case
#: prefixes, whose trailing characters would otherwise read as rulenames --
#: the `s` of `%s"null"` being the one that actually bit.
_TERMINAL = re.compile(r"%[bdxBDX][0-9A-Fa-f]+(?:[.-][0-9A-Fa-f]+)*|%[siSI]")

#: Prose whose contents are a bare rulename, which the loader treats as a
#: reference rather than as prose.
_PROSE_RULENAME = re.compile(r"<([A-Za-z][A-Za-z0-9-]*)>")

Key = tuple[str, str]


def _spans(text: str) -> list[tuple[int, int]]:
    """Character ranges in which a rulename may appear.

    Everything else -- quoted strings, comments, prose, numeric terminals --
    is excluded, so a rulename scan never mistakes the ``s`` of ``%s"null"``
    or the ``x`` in ``"x"`` for a rule.
    """

    blocked: list[tuple[int, int]] = [m.span() for m in _TERMINAL.finditer(text)]
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == '"':
            end = text.find('"', index + 1)
            end = length if end < 0 else end + 1
            blocked.append((index, end))
            index = end
        elif char == ";":
            end = text.find("\n", index)
            end = length if end < 0 else end
            blocked.append((index, end))
            index = end
        elif char == "<":
            end = text.find(">", index)
            end = length if end < 0 else end + 1
            blocked.append((index, end))
            index = end
        else:
            index += 1

    blocked.sort()
    allowed: list[tuple[int, int]] = []
    cursor = 0
    for start, end in blocked:
        if start > cursor:
            allowed.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < length:
        allowed.append((cursor, length))
    return allowed


def _name_matches(text: str) -> list[re.Match[str]]:
    """Every rulename occurrence in ``text``, in order."""

    return [
        match
        for start, end in _spans(text)
        for match in _RULENAME.finditer(text, start, end)
    ]


def normalise_prose(text: str) -> str:
    """Turn ``<rulename>`` into a plain reference, as the loader does.

    ``visit_prose_val`` reparses the contents of prose and returns a rule
    reference when they are a bare rulename.  Prose that is not a rulename is
    left alone: it is a defect, and abnfgen reporting it as an undefined
    nonterminal is the correct outcome.
    """

    return _PROSE_RULENAME.sub(r"\1", text)


def _grammar_text(rule_class: type[Rule]) -> str:
    grammar = rule_class.grammar
    if isinstance(grammar, str):
        return grammar
    # The list form uses backslash continuations, which Python joined when the
    # module was read; each entry is one complete rule.
    return "\n".join(grammar)


def definitions(rule_class: type[Rule]) -> dict[str, str]:
    """Map folded rulename -> ABNF definition, from the module's own text."""

    text = normalise_prose(_grammar_text(rule_class))
    starts = list(_DEFINITION_START.finditer(text))
    found: dict[str, str] = {}
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        name = match.group(1).casefold()
        body = text[match.start() : end].strip()
        if name in found and match.group(2) == "=/":
            # `=/` adds an alternative rather than replacing.
            found[name] = f"{found[name]}\n{body}"
        else:
            # A plain `=` redefinition replaces, which is what the loader does
            # (it warns, but the later definition wins).
            found[name] = body
    return found


def references(definition: str) -> set[str]:
    """Rulenames a definition depends on."""

    _, _, rhs = definition.partition("=")
    return {match.group(0) for match in _name_matches(rhs)}


def _imports_of(rule_class: type[Rule]) -> tuple[tuple[str, Rule], ...]:
    return rule_class._imported_rules  # noqa: SLF001


_CLASSES: dict[str, type[Rule]] = {}


def _register(rule_class: type[Rule]) -> str:
    """Modules are keyed by name; a class is needed to read its text back."""

    key = f"{rule_class.__module__}.{rule_class.__qualname__}"
    _CLASSES[key] = rule_class
    return key


def _deref(
    rule_class: type[Rule], name: str, seen: set[Key] | None = None
) -> Key | None:
    """Resolve ``name`` in ``rule_class`` to the key that actually defines it.

    Imports are followed first, because the loader applies them last and they
    therefore win over the module's own text.
    """

    seen = seen if seen is not None else set()
    key = (_register(rule_class), name.casefold())
    if key in seen:
        return None
    seen.add(key)

    for imported_name, source in _imports_of(rule_class):
        if imported_name.casefold() == name.casefold():
            found = _deref(type(source), source.name, seen)
            if found is not None:
                return found
    if name.casefold() in definitions(rule_class):
        return key
    return None


def _emit_names(keys: list[Key], reserved: dict[str, Key]) -> dict[Key, str]:
    """Assign each key an ABNF name.

    ``reserved`` maps the names the target module exposes to the keys that
    define them; those win, because a caller naming a start rule uses the
    module's own vocabulary.  Anything else keeps its plain name where it can
    and is mangled with its class where it cannot -- a collision only happens
    when two classes define different rules under one name.
    """

    assigned: dict[Key, str] = {}
    taken: set[str] = set()
    for name, key in sorted(reserved.items()):
        if key in assigned:
            # Two exposed names for one definition; the second becomes an
            # alias rather than a second definition.
            continue
        assigned[key] = name
        taken.add(name)

    for key in sorted(set(keys) - set(assigned)):
        module, name = key
        candidate = name
        if candidate in taken:
            stem = module.rsplit(".", 1)[-1].replace("_", "-")
            candidate = f"{stem}-{name}"
            suffix = 2
            while candidate in taken:
                candidate = f"{stem}-{name}-{suffix}"
                suffix += 1
        assigned[key] = candidate
        taken.add(candidate)
    return assigned


def _rewrite(definition: str, name: str, resolve: dict[str, str]) -> str:
    """Rewrite a definition's left-hand side and its rule references."""

    header = _DEFINITION_START.search(definition)
    body_start = header.end() if header else 0
    operator = header.group(2) if header else "="
    body = definition[body_start:]

    pieces: list[str] = []
    cursor = 0
    for match in _name_matches(body):
        target = resolve.get(match.group(0).casefold())
        if target is None:
            continue
        pieces.append(body[cursor : match.start()])
        pieces.append(target)
        cursor = match.end()
    pieces.append(body[cursor:])
    return f"{name} {operator}{''.join(pieces)}"


def effective_grammar(rule_class: type[Rule]) -> tuple[str, set[str]]:
    """Return ``(abnf_text, unresolved_names)`` for a grammar module.

    ``unresolved_names`` excludes the core rules, so anything reported is
    referenced and defined nowhere.
    """

    _register(rule_class)

    # Every name the module answers to: its own text, plus its import list.
    roots: dict[str, Key] = {}
    for name in definitions(rule_class):
        key = _deref(rule_class, name)
        if key is not None:
            roots[name] = key
    for imported_name, _ in _imports_of(rule_class):
        key = _deref(rule_class, imported_name)
        if key is not None:
            roots[imported_name.casefold()] = key

    # Walk the reference graph, resolving each definition's references in the
    # namespace of the class that owns it.
    bodies: dict[Key, str] = {}
    edges: dict[Key, dict[str, Key]] = {}
    unresolved: set[str] = set()
    pending = list(roots.values())
    while pending:
        key = pending.pop()
        if key in bodies:
            continue
        module, name = key
        owner = _CLASSES[module]
        bodies[key] = definitions(owner)[name]
        mapping: dict[str, Key] = {}
        for ref in references(bodies[key]):
            if ref.casefold() in _CORE_FOLDED:
                continue
            target = _deref(owner, ref)
            if target is None:
                unresolved.add(ref)
                continue
            mapping[ref.casefold()] = target
            pending.append(target)
        edges[key] = mapping

    names = _emit_names(list(bodies), roots)

    lines = [
        _rewrite(
            bodies[key],
            names[key],
            {ref: names[target] for ref, target in edges[key].items()},
        )
        for key in sorted(bodies, key=lambda k: names[k])
    ]

    # A module may expose a rule under a name the definition does not carry --
    # rfc7230's `uri-host` is RFC 3986's `host` -- and a caller naming a start
    # rule uses the module's name.  An alias costs one production and keeps
    # every other definition unchanged.
    lines += [
        f"{name} = {names[key]}"
        for name, key in sorted(roots.items())
        if names[key].casefold() != name.casefold()
    ]

    return "\n".join(lines), unresolved
