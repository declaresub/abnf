import pytest

from abnf.grammars import rfc9116
from abnf.parser import ParseError


@pytest.mark.parametrize("src", [
'''-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA512\r\n\r\nContact: charles@declaresub.com\r\nExpires: 2023-03-14T00:00:00.000Z\r\n-----BEGIN PGP SIGNATURE-----\r\n\r\niHUEARYKAB0WIQSsP2kEdoKDVFpSg6u3rK+YCkjapwUCYhjpQwAKCRC3rK+YCkjapyk2AP97ePaFUo8K8e1D+N+G6caqXjC/pwnZB+Wkk15AI+xstgD/VR5rOLKLZ7QFgKk5ohVS7qHou8Ux9cdodY2BRUIdrww==gFfQ\r\n-----END PGP SIGNATURE-----\r\n''',
])
def test_securitytxt_contact(src: str):
    assert rfc9116.Rule('body').parse_all(src)


# Issue #237: token-char was transcribed as %x21-27 / ... , which swept in
# DQUOTE (a tspecial) and omitted "-" and "." (which are not).
@pytest.mark.parametrize('src', ['SHA-256', 'v1.0', 'token', 'a{b', 'a~b'])
def test_237_token_accepts(src: str):
    assert rfc9116.Rule('token').parse_all(src).value == src


@pytest.mark.parametrize('src', ['a"b', 'a b', 'a,b', 'a@b', 'a/b', 'a[b'])
def test_237_token_rejects_tspecials(src: str):
    with pytest.raises(ParseError):
        rfc9116.Rule('token').parse_all(src)


def test_237_hash_alg_takes_the_usual_value():
    """`SHA-256` is what a PGP Hash: header actually carries."""
    assert rfc9116.Rule('hash-alg').parse_all('SHA-256').value == 'SHA-256'


# RFC 9116 writes `comment = "#" *(WSP / VCHAR / %x80-FFFFF)`, and that range
# spans D800-DFFF -- so a comment may contain a surrogate.  abnf indexes by
# code point since 2.8.1 (issue #173) and accepts them; before that the rust
# backend worked in `char`, which cannot represent one at all.
#
# The abnfgen corpus reaches this only at particular seeds, which is no basis
# for coverage, so it is pinned here.
@pytest.mark.parametrize(
    'src',
    [
        '#\ud800\r\n',                # low end of the surrogate block
        '#\udfff\r\n',                # high end
        '#\t\udb73\U000622c7\r\n',    # the case abnfgen actually produced
        '#\U000fffff\r\n',            # top of the range the RFC names
    ],
)
def test_comment_admits_the_whole_range_rfc_9116_names(src: str):
    assert rfc9116.Rule('line').parse_all(src).value == src


@pytest.mark.parametrize('src', ['#\U00100000\r\n', '#\U0010ffff\r\n'])
def test_comment_stops_where_rfc_9116_stops(src: str):
    """%x80-FFFFF ends at U+FFFFF; code points above it are not admitted."""
    with pytest.raises(ParseError):
        rfc9116.Rule('line').parse_all(src)
