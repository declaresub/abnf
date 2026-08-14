//! `Parser` enum and shared type aliases.

use std::sync::Arc;

use smallvec::SmallVec;

use crate::alternation::Alternation;
use crate::concatenation::Concatenation;
use crate::literal::Literal;
use crate::matcher::Match;
use crate::node::NodeKind;
use crate::option::OptionParser;
use crate::prose::Prose;
use crate::repetition::Repetition;
use crate::rule::NamedRule;

/// The source, as the parser sees it: a sequence of Unicode code
/// points.
///
/// Not `&str`.  `abnf` parses code points -- a num-val names one, and
/// a Python `str` is a sequence of them -- and that domain is wider
/// than Rust's text types: `char` is a Unicode *scalar value* and
/// `str` is well-formed UTF-8, so neither can hold a surrogate.
/// Surrogates reach a parser in ordinary use (`surrogateescape` is
/// how Python represents undecodable filenames and `sys.argv`), and a
/// grammar may name them outright with `%xD800-DBFF`.  Indexing is by
/// code point throughout, which is also the unit the Python API has
/// always exposed for `offset` and `start` -- so no translation
/// happens at the boundary any more (issue #173).
pub type Src<'a> = &'a [u32];

/// Inline-stored node list.  Most match boundaries between
/// combinators carry exactly one node (a `NamedRule` wrap produces
/// a single-node match), so inlining 1 element covers the hot path
/// without bloating `Match` enough to hurt cache locality.  Larger
/// node lists (the growing prefix accumulated inside
/// `Concatenation`/`Repetition`) spill to the heap, which matches
/// the original allocation pattern.
pub type NodeList = SmallVec<[NodeKind; 1]>;

/// Inline-stored match list.  Deterministic grammars (the
/// overwhelming majority of rules in real RFCs) produce exactly one
/// match per combinator call; ambiguous grammars spill to the heap.
pub type MatchList = SmallVec<[Match; 1]>;

/// Result of a single combinator's `lparse`.
pub type ParseResult = Result<MatchList, crate::error::ParseError>;

/// Shared parser handle used to compose trees.
pub type ArcParser = Arc<Parser>;

/// External parser callback — used by the PyO3 layer to embed a
/// foreign (Python-side) parser object inside a Rust combinator tree.
///
/// Implementors are responsible for marshalling their own
/// `lparse(source, start) -> matches` semantics into the
/// [`ParseResult`] shape.
pub trait ExternalParser: std::fmt::Debug + Send + Sync + 'static {
    fn lparse(&self, source: Src<'_>, start: usize) -> ParseResult;
}

/// Tagged union over every combinator type.
#[derive(Debug)]
pub enum Parser {
    Alternation(Alternation),
    Concatenation(Concatenation),
    Repetition(Repetition),
    Option(OptionParser),
    Literal(Literal),
    Prose(Prose),
    Rule(Arc<NamedRule>),
    External(Arc<dyn ExternalParser>),
}

impl Parser {
    pub fn lparse(&self, source: Src<'_>, start: usize) -> ParseResult {
        match self {
            Parser::Alternation(p) => p.lparse(source, start),
            Parser::Concatenation(p) => p.lparse(source, start),
            Parser::Repetition(p) => p.lparse(source, start),
            Parser::Option(p) => p.lparse(source, start),
            Parser::Literal(p) => p.lparse(source, start),
            Parser::Prose(p) => p.lparse(source, start),
            Parser::Rule(p) => p.lparse(source, start),
            Parser::External(p) => p.lparse(source, start),
        }
    }
}

// `From<X> for Parser` lets each combinator type be lifted into the
// enum via `.into()`.  The orphan rule blocks the corresponding
// `From<X> for Arc<Parser>` direct impl, so the call sites combine
// `.into()` with the `arc(...)` helper below to materialise an
// `ArcParser` in one go: `arc(Alternation::new(...))`.

impl From<Alternation> for Parser {
    fn from(a: Alternation) -> Self {
        Parser::Alternation(a)
    }
}

impl From<Concatenation> for Parser {
    fn from(c: Concatenation) -> Self {
        Parser::Concatenation(c)
    }
}

impl From<Repetition> for Parser {
    fn from(r: Repetition) -> Self {
        Parser::Repetition(r)
    }
}

impl From<OptionParser> for Parser {
    fn from(o: OptionParser) -> Self {
        Parser::Option(o)
    }
}

impl From<Literal> for Parser {
    fn from(l: Literal) -> Self {
        Parser::Literal(l)
    }
}

impl From<Prose> for Parser {
    fn from(p: Prose) -> Self {
        Parser::Prose(p)
    }
}

impl From<Arc<NamedRule>> for Parser {
    fn from(r: Arc<NamedRule>) -> Self {
        Parser::Rule(r)
    }
}

/// Wrap any combinator (or named-rule handle) into an `ArcParser`.
pub fn arc<T: Into<Parser>>(p: T) -> ArcParser {
    Arc::new(p.into())
}

// Direct `From<X> for ArcParser` impls so call sites can write
// `Alternation::new(...).into()` and have it produce an `ArcParser`
// in one step.  Orphan-rule safe because the source `X` is always a
// type local to this crate.

impl From<Alternation> for ArcParser {
    fn from(a: Alternation) -> Self {
        Arc::new(Parser::Alternation(a))
    }
}

impl From<Concatenation> for ArcParser {
    fn from(c: Concatenation) -> Self {
        Arc::new(Parser::Concatenation(c))
    }
}

impl From<Repetition> for ArcParser {
    fn from(r: Repetition) -> Self {
        Arc::new(Parser::Repetition(r))
    }
}

impl From<OptionParser> for ArcParser {
    fn from(o: OptionParser) -> Self {
        Arc::new(Parser::Option(o))
    }
}

impl From<Literal> for ArcParser {
    fn from(l: Literal) -> Self {
        Arc::new(Parser::Literal(l))
    }
}

impl From<Prose> for ArcParser {
    fn from(p: Prose) -> Self {
        Arc::new(Parser::Prose(p))
    }
}
