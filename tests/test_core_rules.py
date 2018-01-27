import pytest
from itertools import chain, product

from abnf.parser import Rule, ParseError



@pytest.mark.parametrize("src", [chr(x) for x in chain(range(0x41, 0x5b), range(0x61, 0x7b))])
def test_ALPHA(src):
    node, start = Rule('ALPHA').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['0', '1'])
def test_BIT(src):
    node, start = Rule('BIT').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [chr(x) for x in range(0x01, 0x80)])
def test_CHAR(src):
    node, start = Rule('CHAR').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['\r'])
def test_CR(src):
    node, start = Rule('CR').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['\r\n'])
def test_CRLF(src):
    node, start = Rule('CRLF').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [chr(x) for x in chain(range(0x00, 0x20), [0x7f])])
def test_CTL(src):
    node, start = Rule('CTL').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [chr(x) for x in range(0x30, 0x3a)])
def test_DIGIT(src):
    node, start = Rule('DIGIT').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['"'])
def test_DQUOTE(src):
    node, start = Rule('DQUOTE').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F'])
def test_HEXDIG(src):
    node, start = Rule('HEXDIG').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['\t'])
def test_HTAB(src):
    node, start = Rule('HTAB').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['\n'])
def test_LF(src):
    node, start = Rule('LF').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [''] + [x*y for x, y in product([1, 2], [' ', '\t', '\r\n ', '\r\n\t'])])
def test_LWSP(src):
    node, start = Rule('LWSP').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [chr(x) for x in range(0x00, 0x100)])
def test_OCTET(src):
    node, start = Rule('OCTET').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [' '])
def test_SP(src):
    node, start = Rule('SP').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [chr(x) for x in range(0x21, 0x7f)])
def test_VCHAR(src):
    node, start = Rule('VCHAR').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [' ', '\t'])
def test_WSP(src):
    node, start = Rule('WSP').parse(src, 0)
    assert node and node.value == src
