# Explanation

Understanding-oriented discussion of how and why abnf works the way it does.
These pages are for background reading, not step-by-step instructions.

- {doc}`what-abnf-parses` — code points, not bytes: what a terminal value means
  and how to parse wire data.
- {doc}`architecture` — parser combinators and the self-bootstrapping meta-grammar.
- {doc}`backends` — the pure-Python and Rust implementations behind one API.
- {doc}`alternation-semantics` — longest match vs. first match, and why it's a choice.
- {doc}`backtracking-and-caching` — how exponential blow-up is kept in check.
- {doc}`rust-backend-performance` — where the Rust backend wins big and where the
  gap narrows.
