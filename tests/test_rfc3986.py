import pytest

from abnf.grammars import rfc3986


@pytest.mark.parametrize('src, value', [
# test added thanks to https://github.com/declaresub/abnf/issues/10.
('2001:0db8:0000:0000:0000:ff00:0042:8329', '2001:0db8:0000:0000:0000:ff00:0042:8329'), 
('2001:db8:cafe::17', '2001:db8:cafe::17'),
('0:0:0:0:0:ffff:192.1.56.10', '0:0:0:0:0:ffff:192.1.56.10'),
('::', '::'),
])
def test_IPv6address(src: str, value: str):
    ip6 = rfc3986.Rule('IPv6address')
    assert ip6.parse_all(src).value == value


# Issue #24: `path` lists `path-abempty` first, and `path-abempty` is
# `*( "/" segment )`, which matches the empty string -- so under first-match
# alternation it would swallow every input.  Under the default (longest match)
# it does not, and these tests pin that rather than reordering the grammar
# away from the RFC's own text.
@pytest.mark.parametrize(
    'src, alternative',
    [
        ('/a/b/c', 'path-abempty'),
        ('/', 'path-abempty'),
        ('//x', 'path-abempty'),
        ('', 'path-abempty'),
        ('a/b/c', 'path-noscheme'),
        ('a', 'path-noscheme'),
        # ':' is a pchar but not a segment-nz-nc char, so path-noscheme stops
        # at the colon and the longer path-rootless wins.
        ('a:b/c', 'path-rootless'),
        ('x%20y/z', 'path-noscheme'),
    ],
)
def test_24_path_consumes_the_whole_input(src: str, alternative: str):
    node = rfc3986.Rule('path').parse_all(src)
    assert node.value == src
    assert [child.name for child in node.children] == [alternative]


@pytest.mark.parametrize(
    'rule, src, alternative',
    [
        # path-empty is not dead: it is how an empty path is matched where
        # path-abempty is not among the alternatives being tried.
        ('hier-part', '', 'path-empty'),
        ('relative-part', '', 'path-empty'),
        ('hier-part', '/a/b', 'path-absolute'),
        ('relative-part', 'a/b', 'path-noscheme'),
    ],
)
def test_24_empty_and_relative_paths(rule: str, src: str, alternative: str):
    node = rfc3986.Rule(rule).parse_all(src)
    assert node.value == src
    assert alternative in [child.name for child in node.children]


@pytest.mark.parametrize('src', ['mailto:', 'urn:ietf:rfc:2648', 'http://example.com'])
def test_24_uri_with_empty_or_rootless_path(src: str):
    assert rfc3986.Rule('URI').parse_all(src).value == src
