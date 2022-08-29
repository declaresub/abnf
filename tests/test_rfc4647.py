import pytest

from abnf.grammars import rfc4647


@pytest.mark.parametrize('src', [
# test added thanks to https://github.com/declaresub/abnf/issues/10.
'en',
'en-US',
])
def test_language_range(src: str):
    ip6 = rfc4647.Rule('language-range')
    assert ip6.parse_all(src)



@pytest.mark.parametrize('src', [
# test added thanks to https://github.com/declaresub/abnf/issues/10.
'*-*-foo',
])
def test_extended_language_range(src: str):
    ip6 = rfc4647.Rule('extended-language-range')
    assert ip6.parse_all(src)
