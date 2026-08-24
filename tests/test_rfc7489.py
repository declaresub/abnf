import pytest

from abnf.grammars import rfc7489
from abnf.parser import ParseError, Source


def test_valid_dmarc_version():
    version = rfc7489.Rule('dmarc-version')
    assert version.parse_all("v=DMARC1")
    assert version.parse_all("v =  DMARC1")
    assert version.parse_all("V =  DMARC1")


@pytest.mark.parametrize("src", [
    'mailto:olivier@hureau.com',
    'mailto:olivier@hureau.com!50m',
    'mailto:olivier@hureau.com!50',
    'mailto:olivier@hureau.com!50'
])

def test_valid_dmarc_uri(src: Source):
    uri = rfc7489.Rule('dmarc-uri')
    assert uri.parse_all(src)

@pytest.mark.parametrize("src", [
    ';',
    ' ;',
    '; ',
    '\t;'
])

def test_valid_dmarc_seperator(src: Source):
    separator = rfc7489.Rule('dmarc-sep')
    assert separator.parse_all(src)

@pytest.mark.parametrize("src", [
    'p=none', 'p=reject', 'p=quarantine',
    'P=none', 'p=NoNe',
    'p =    none'
])

def test_valid_dmarc_request(src: Source):
    request = rfc7489.Rule('dmarc-request')
    assert request.parse_all(src)

@pytest.mark.parametrize("src", [
    'sp=none', 'sp=reject', 'sp=quarantine',
    'sP=none', 'Sp=NoNe',
    'sp =    none'
])

def test_valid_dmarc_srequest(src: Source):
    srequest = rfc7489.Rule('dmarc-srequest')
    assert srequest.parse_all(src)

@pytest.mark.parametrize("src", [
    'rua=mailto:olivier@hureau.com',
    'RUA=mailto:olivier@hureau.com!50m',
    'rua  =   mailto:olivier@hureau.com!50',
    'rua=mailto:olivier@hureau.com, mailto:olivier@hureau.com',
    'rua=  mailto:olivier@hureau.com   , mailto:olivier@hureau.com   '
])

def test_valid_dmarc_auri(src: Source):
    auri = rfc7489.Rule('dmarc-auri')
    assert auri.parse_all(src)

@pytest.mark.parametrize("src", [
    'ruf=mailto:olivier@hureau.com',
    'RUF=mailto:olivier@hureau.com!50m',
    'ruf  =   mailto:olivier@hureau.com!50',
    'ruf=mailto:olivier@hureau.com, mailto:olivier@hureau.com',
    'ruf=  mailto:olivier@hureau.com   , mailto:olivier@hureau.com   '
])

def test_valid_dmarc_furi(src: Source):
    auri = rfc7489.Rule('dmarc-furi')
    assert auri.parse_all(src)

@pytest.mark.parametrize("src", [
    'aspf=s',
    'aspf=r',
    'aspf=R',
    'aspf=S',
    'aspf = s',
    'aSPf = s',
])

def test_valid_dmarc_aspf(src: Source):
    aspf = rfc7489.Rule('dmarc-aspf')
    assert aspf.parse_all(src)

@pytest.mark.parametrize("src", [
    'ri=8600',
    'ri  = 8600',
    'RI = 8600'
])

def test_valid_dmarc_ri(src: Source):
    interval = rfc7489.Rule('dmarc-ainterval')
    assert interval.parse_all(src)

@pytest.mark.parametrize("src", [
    'fo=1',
    'fo=  1',
    'fo=1:d:s',
    'fo=1 :  d: s',
    'FO=1',
    'fo=1:1:1:1', # This one should not pass but abnf is abnf...
])

def test_valid_dmarc_fo(src: Source):
    fo = rfc7489.Rule('dmarc-fo')
    assert fo.parse_all(src)

@pytest.mark.parametrize("src", [
    'rf=afrf',
    'RF=afrf',
    'rf  =  afrf',
    'rf=aFrF',
])

def test_valid_dmarc_rf(src: Source):
    rf = rfc7489.Rule('dmarc-rfmt')
    assert rf.parse_all(src)

@pytest.mark.parametrize("src", [
    'pct=100',
    'pct=99',
    'pct=5',
    'pct=0',
    'PCT=0',
    'PCT  =  0'
])

def test_valid_dmarc_pct(src: Source):
    pct = rfc7489.Rule('dmarc-percent')
    assert pct.parse_all(src)

@pytest.mark.parametrize("src", [
    'v=DMARC1;p=reject;',
    'v=DMARC1;p=reject;sp=quarantine;rua=mailto:olivier@hureau.com;ruf=mailto:olivier@hureau.com;adkim=s;aspf=s;ri=2400;fo=1:d:s;rf=afrf;pct=0;'
])

def test_valid_dmarc_record(src: Source):
    record = rfc7489.Rule('dmarc-record')
    assert record.parse_all(src)


# Issue #233: `dmarc-record` required the `p` tag and a trailing separator,
# both of which RFC 7489 section 6.4 brackets as optional.  The first record
# below is the one printed in the RFC's own section B.1.1.
@pytest.mark.parametrize(
    'src',
    [
        'v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com',
        'v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com; '
        'ruf=mailto:auth-reports@example.com',
        'v=DMARC1; rua=mailto:d@example.com',        # no p tag at all
        'v=DMARC1; p=none;',                          # trailing separator still allowed
        'v=DMARC1;',                                  # nothing but the version
        'v=DMARC1; p=quarantine; pct=50; adkim=s; aspf=r',
        'v=DMARC1; sp=reject; fo=1:d; rf=afrf; ri=86400',
    ],
)
def test_233_valid_dmarc_records(src: Source):
    assert rfc7489.Rule('dmarc-record').parse_all(src).value == src


@pytest.mark.parametrize(
    'src',
    [
        'v=DMARC1',            # the separator after the version is required
        'p=none; v=DMARC1;',   # the version must come first
        'v=DMARC2; p=none;',   # wrong version
        '',
    ],
)
def test_233_invalid_dmarc_records(src: Source):
    with pytest.raises(ParseError):
        rfc7489.Rule('dmarc-record').parse_all(src)


@pytest.mark.parametrize('src', ['mailto:d@example.com', 'MAILTO:d@example.com'])
def test_233_uri_scheme_is_case_insensitive(src: Source):
    """RFC 3986 section 3.1: the scheme is case-insensitive.  The rule was
    written with %x literals, which are not."""
    assert rfc7489.Rule('URI').parse_all(src).value == src
