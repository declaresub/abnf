import pytest

from abnf.grammars import rfc7489
from abnf.parser import Source


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



