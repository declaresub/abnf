"""
Collected rules from fetch standard
https://fetch.spec.whatwg.org/#cors-protocol
"""

from typing import ClassVar, Union

from abnf.parser import Rule as _Rule

from . import rfc3986, rfc7230, rfc7234
from .misc import load_grammar_rules


@load_grammar_rules(
    [
        ("scheme", rfc3986.Rule("scheme")),
        ("host", rfc3986.Rule("host")),
        ("port", rfc3986.Rule("port")),
        ("method", rfc7230.Rule("method")),
        ("field-name", rfc7230.Rule("field-name")),
        ("OWS", rfc7230.Rule("OWS")),
        ("delta-seconds", rfc7234.Rule("delta-seconds")),
    ]
)
class Rule(_Rule):
    grammar: ClassVar[Union[list[str], str]] = [
        "Origin = origin-or-null",
        "origin-or-null = origin / %x6E.75.6C.6C",
        'origin = scheme "://" host [ ":" port ]',
        "Access-Control-Request-Method = method",
        'Access-Control-Request-Headers = field-name *( OWS "," OWS field-name )',
        'wildcard = "*"',
        "Access-Control-Allow-Origin = origin-or-null / wildcard",
        "Access-Control-Allow-Credentials = %x74.72.75.65",
        'Access-Control-Expose-Headers = [ field-name *( OWS "," OWS field-name ) ]',
        "Access-Control-Max-Age = delta-seconds",
        'Access-Control-Allow-Methods = [ method *( OWS "," OWS method ) ]',
        'Access-Control-Allow-Headers = [ field-name *( OWS "," OWS field-name ) ]',
    ]
