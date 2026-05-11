"""Cross-backend parse performance benchmarks.

Run with ``pytest tests/benchmarks/``.  Compare the Python and Rust
backends by forcing each via the ``ABNF_NO_RUST`` environment
variable before the abnf package is imported.

The benchmark suite picks one representative rule from each of
four widely-used grammars and parses a short, real-world-shaped
input.  ``pytest-benchmark`` reports min/mean/median timings; run
both backends in turn to compute speed-up ratios.
"""

import pytest

from abnf.grammars import rfc3986, rfc5322, rfc7230, rfc9051
from abnf.parser import _BACKEND


@pytest.fixture(scope="session")
def backend_label() -> str:
    return _BACKEND


# ----------------------------------------------------------------
# Workload definitions
# ----------------------------------------------------------------

_CASES = [
    (
        "rfc7230_request_line",
        rfc7230,
        "request-line",
        "GET /index.html HTTP/1.1\r\n",
    ),
    (
        "rfc3986_uri",
        rfc3986,
        "URI",
        "https://user:pass@example.com:8080/a/b/c?q=1&r=2#frag",
    ),
    (
        "rfc5322_mailbox",
        rfc5322,
        "mailbox",
        "Charles Yeomans <charles@example.com>",
    ),
    (
        "rfc9051_astring",
        rfc9051,
        "astring",
        "HelloWorld42",
    ),
]


@pytest.mark.parametrize(
    ("label", "module", "rule_name", "source"),
    _CASES,
    ids=[c[0] for c in _CASES],
)
def test_parse(benchmark, label, module, rule_name, source, backend_label):
    """Benchmark one parse call per iteration.

    The benchmark fixture re-creates the timing context but reuses
    the rule object across iterations, mirroring real-world usage
    where the rule is constructed once at import and parsed many
    times.
    """
    rule = module.Rule(rule_name)
    # Sanity-check that the rule actually parses the input before
    # benchmarking; an early ParseError would otherwise pollute the
    # numbers.
    rule.parse_all(source)
    benchmark.group = f"{label}::{backend_label}"
    benchmark(rule.parse_all, source)
