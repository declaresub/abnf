import pytest
import os
import io

from abnf.parser import ABNFGrammarRule, ParseError


# fuzz test data generated using abnfgen <http://www.quut.com/abnfgen/>.

FUZZ_DIR = 'tests/fuzz'

def load_fuzz_test_data(dirname):
    test_data = []
    dir = os.path.join(FUZZ_DIR, dirname)
    for filename in os.listdir(dir):
        with io.open(os.path.join(dir, filename), 'rb') as f:
            test_data.append(f.read().decode('utf-8'))
            
    return test_data

@pytest.mark.parametrize("src", load_fuzz_test_data('char-val'))
def test_char_val(src):
    node, start = ABNFGrammarRule('char-val').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", load_fuzz_test_data('num-val'))    
def test_num_val(src):
    node, start = ABNFGrammarRule('num-val').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", load_fuzz_test_data('repeat'))
def test_repeat(src):
    node, start = ABNFGrammarRule('repeat').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", load_fuzz_test_data('comment'))
def test_comment(src):
    node, start = ABNFGrammarRule('comment').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", [
""";foo\r\n""",
"""\r\n"""])
def test_c_nl(src):
    node, start = ABNFGrammarRule('c-nl').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", load_fuzz_test_data('c-wsp'))
def test_c_wsp(src):
    node, start = ABNFGrammarRule('c-wsp').parse(src, 0)
    assert node and node.value == src

@pytest.mark.parametrize("src", load_fuzz_test_data('rule'))
def test_rule(src):
    node, start = ABNFGrammarRule('rule').parse(src, 0)
    assert node and node.value == src