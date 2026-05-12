# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** through one of:

1. **GitHub Security Advisories** — preferred. Open a private report at
   <https://github.com/declaresub/abnf/security/advisories/new>. This
   keeps the issue confidential until a fix is available and produces
   a CVE if appropriate.

2. **Email** — `charles@declaresub.com`. Use this if you cannot use
   GitHub advisories. Please include "abnf security" in the subject.

Do **not** open a public GitHub issue or pull request for a suspected
security vulnerability. Public disclosure before a fix is available
exposes downstream users.

## What to include

- A short description of the issue and its impact.
- Steps to reproduce (a minimal grammar or source input is ideal).
- The version of `abnf` (and `abnf-rust` if relevant) that you tested.
- Your Python version and platform.

## Response

This project is maintained by a single volunteer. Realistic timeline:

- **Acknowledgement**: within 7 days.
- **Initial assessment**: within 21 days.
- **Fix and release**: depends on severity and complexity. Critical
  issues will be prioritized; lower-severity issues are addressed on a
  best-effort basis.

If you do not hear back within 7 days, please follow up via the other
channel above.

## Supported versions

The current release line is `2.5.x`.  Security fixes for the previous
minor line are issued on a best-effort basis.

| Version | Status                  |
| ------- | ----------------------- |
| 2.5.x   | Supported (current)     |
| 2.4.x   | Supported (best-effort) |
| < 2.4   | End-of-life             |

## Scope

In scope:

- Memory-safety bugs in the Rust extension (`abnf-rust`).
- Parser misbehaviour producing wrong parse trees that downstream
  protocol parsers rely on for security decisions.
- Supply-chain compromises affecting how `abnf` or `abnf-rust` are
  built, signed, or published.

Out of scope (but please still report if you think it matters):

- Performance / DoS issues caused by the inherent worst-case
  complexity of parser-combinator backtracking. Downstream callers
  parsing untrusted input are expected to enforce a wall-clock
  timeout and to bound `ParseCache` size; see
  [`Rule.max_cache_size`](src/abnf/_parser_python.py).
- Behaviour resulting from a downstream caller passing user-supplied
  ABNF grammar strings to `Rule.create` / `Rule.load_grammar`. The
  grammar-loading path is intended for grammars authored by the
  application, not by its users.

## Disclosure

I aim to disclose fixed vulnerabilities via:

- A patch release on PyPI.
- A GitHub release note and CHANGELOG entry.
- A published security advisory (when reported via the GitHub flow).

Reporters will be credited unless they prefer to remain anonymous.
