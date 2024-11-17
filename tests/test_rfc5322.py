#add tests for comment, specials, obs-qp for backslash.

import pytest

from abnf.grammars import rfc5322
from abnf.parser import ParseError


@pytest.mark.parametrize("src", [
    r'simple@example.com', 
    r'very.common@example.com', 
    r'disposable.style.email.with+symbol@example.com', 
    r'other.email-with-hyphen@example.com', 
    r'fully-qualified-domain@example.com', 
    r'user.name+tag+sorting@example.com',
    r'x@example.com',
    r'example-indeed@strange-example.com',
    r'admin@mailserver1',
    r'example@s.example',
    r'" "@example.org',
    r'"john..doe"@example.org',
    r'mailhost!username@example.org',
    r'user%example.com@example.org',
    ])
def test_address(src: str):
    rfc5322.Rule('address').parse_all(src)

@pytest.mark.parametrize("src", [
    r'Abc.example.com', # (no @ character)
    r'A@b@c@example.com', # (only one @ is allowed outside quotation marks)
    r'a"b(c)d,e:f;g<h>i[j\k]l@example.com', # (none of the special characters in this local-part are allowed outside quotation marks)
    r'just"not"right@example.com', # (quoted strings must be dot separated or the only element making up the local-part)
    r'this is"not\allowed@example.com', # (spaces, quotes, and backslashes may only exist when within quoted strings and preceded by a backslash)
    r'this\ still\"not\\allowed@example.com', # (even if escaped (preceded by a backslash), spaces, quotes, and backslashes must still be contained by quotes)
    ])    
def test_address_bad(src: str):
    with pytest.raises(ParseError):
        rfc5322.Rule('address').parse_all(src)

@pytest.mark.parametrize("src", [
'''From: John Doe <jdoe@machine.example>\r\nTo: Mary Smith <mary@example.net>\r\nSubject: Saying Hello\r\nDate: Fri, 21 Nov 1997 09:55:06 -0600\r\nMessage-ID: <1234@local.machine.example>\r\n\r\n
This is a message just to say hello.
So, "Hello".''',


]
)
def test_parse_example(src: str):
    rfc5322.Rule('message').parse_all(src)

