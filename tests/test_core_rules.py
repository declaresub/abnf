import pytest
from itertools import chain, product

from abnf.parser import Rule, ParseError



@pytest.mark.parametrize("src", [chr(x) for x in chain(range(0x41, 0x5b), range(0x61, 0x7b))])
def test_ALPHA(src):
    node, _ = Rule('ALPHA').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['0', '1'])
def test_BIT(src):
    node, _ = Rule('BIT').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [chr(x) for x in range(0x01, 0x80)])
def test_CHAR(src):
    node, _ = Rule('CHAR').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['\r'])
def test_CR(src):
    node, _ = Rule('CR').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['\r\n'])
def test_CRLF(src):
    node, _ = Rule('CRLF').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [chr(x) for x in chain(range(0x00, 0x20), [0x7f])])
def test_CTL(src):
    node, _ = Rule('CTL').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [chr(x) for x in range(0x30, 0x3a)])
def test_DIGIT(src):
    node, _ = Rule('DIGIT').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['"'])
def test_DQUOTE(src):
    node, _ = Rule('DQUOTE').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F'])
def test_HEXDIG(src):
    node, _ = Rule('HEXDIG').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['\t'])
def test_HTAB(src):
    node, _ = Rule('HTAB').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", ['\n'])
def test_LF(src):
    node, _ = Rule('LF').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [''] + [x*y for x, y in product([1, 2], [' ', '\t', '\r\n ', '\r\n\t'])])
def test_LWSP(src):
    node, _ = Rule('LWSP').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [chr(x) for x in range(0x00, 0x100)])
def test_OCTET(src):
    node, _ = Rule('OCTET').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [' '])
def test_SP(src):
    node, _ = Rule('SP').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [chr(x) for x in range(0x21, 0x7f)])
def test_VCHAR(src):
    node, _ = Rule('VCHAR').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [' ', '\t'])
def test_WSP(src):
    node, _ = Rule('WSP').parse(src, 0)
    assert node and node.value == src
