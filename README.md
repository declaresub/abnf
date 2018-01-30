# ABNF

ABNF is a package that generates parsers from ABNF grammars.  The main purpose of this
package is to parse data as specified in RFCs.  But it should be able to handle any ABNF 
grammar.

## Requirements

ABNF has been tested with Python 3.4-6.  Support for Python 2 is not planned at this time.

## Usage

The main class of abnf is Rule.  A Rule object is a parser created from an ABNF rule.

    from abnf import Rule
    rule = Rule.create('URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]')
    
Once created, a Rule object is retrieved by name.

    rule = Rule('URI')
    
The Rule class is initialized with the core ABNF rules OCTET, BIT, HEXDIG, CTL, HTAB, LWSP, 
CR, VCHAR, DIGIT, WSP, DQUOTE, LF, SP, CRLF, CHAR, ALPHA.

Rule objects are cached, so `Rule('URI')` should always return the same object.  Objects 
are stored internally by class and casefolded name, so it is possible that loading multiple 
grammars will result in rulename collisions.  Thus you usually want to define a Rule
subclass for each grammar. The core rules are available in subclasses.

ABNF includes several grammars.  The Rule subclass ABNFGrammarRule implements the rules 
for ABNF.  The package `abnf.grammars` includes grammars from several RFCs.

    >>> from abnf.grammars import rfc7232
    >>> src = 'W/"moof"'
    >>> node, start = rfc7232.Rule('ETag').parse(src)
    >>> print(str(node))
    Node(name=ETag, children=[Node(name=entity-tag, children=[Node(name=weak, children=[Node(name=literal, value="W/")]), Node(name=opaque-tag, children=[Node(name=DQUOTE, children=[Node(name=literal, value=""")]), Node(name=etagc, children=[Node(name=literal, value="m")]), Node(name=etagc, children=[Node(name=literal, value="o")]), Node(name=etagc, children=[Node(name=literal, value="o")]), Node(name=etagc, children=[Node(name=literal, value="f")]), Node(name=DQUOTE, children=[Node(name=literal, value=""")])])])])


The modules in `abnf.grammars` may serve as an example for writing other Rule subclasses. 
In particular, some of the RFC grammars incorporate rules by reference from other RFC. 
`abnf.grammars.rfc7230` shows a way to import rules.

ABNF uses CRLF as a delimiter for rules.  Because many text editors (e.g. BBEdit) substitute line endings 
without telling the user, ABNF expects preprocessing of grammars into python lists of rules as 
in `abnf.grammars`.


## Development, Testing, etc.

I create virtual environments for development in a directory venv. Should you wish 
to do the same (with cwd = repository root):

    python3.4 -m venv venv/py34
    python3.5 -m venv venv/py35
    python3.6 -m venv venv/py36
    
Activate the virtual environment of your choice:

    source venv/py34/bin/activate

and install an editable version of the project plus various tools.

    pip install -r venv/requirements.txt

Among the tools I use is [yapf](https://github.com/google/yapf) for code formatting.

The test suite includes fuzz testing with test data generated using [abnfgen](http://www.quut.com/abnfgen/).
Some of the test rules are long and gruesome.  Thus the tests take a bit of time to complete.

## Implementation

abnf is implemented using parser combinators.  As a result, error reporting is not what it
might be.
