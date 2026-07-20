# Extract values from a parse tree

Parsing gives you a tree of `Node` objects. There are two common ways to pull data
out of it: a quick manual traversal, or a `NodeVisitor` for anything structured.

```{note}
Treat a returned parse tree as read-only. Cache hits can cause trees from repeated
parses of the same input to share descendant `Node` objects, so mutating one tree
in place can affect another.
```

## Quick traversal

For a one-off lookup, walk the tree yourself. A node's `name` is its rule name and
`value` is the source text it matched:

```python
from abnf.grammars import rfc5322

def find_value(node, rule_name):
    """Breadth-first search for the first node with the given rule name."""
    queue = [node]
    while queue:
        n, queue = queue[0], queue[1:]
        if n.name == rule_name:
            return n.value
        queue.extend(n.children)
    return None

node = rfc5322.Rule("address").parse_all("John Doe <jdoe@example.com>")
find_value(node, "addr-spec")   # 'jdoe@example.com'
```

## NodeVisitor

For anything beyond a single lookup, subclass `NodeVisitor`. Define a
`visit_<rule_name>` method for each rule you care about (hyphens in rule names
become underscores); dispatch is reflective, and `visit(node)` routes to the right
method as you walk. This example pulls the scheme and token out of an HTTP
`Authorization` header:

```python
from abnf import NodeVisitor
from abnf.grammars import rfc7235

class AuthVisitor(NodeVisitor):
    def __init__(self):
        super().__init__()
        self.auth_scheme = None
        self.token = None

    def visit_authorization(self, node):
        for child in node.children:
            self.visit(child)

    def visit_credentials(self, node):
        for child in node.children:
            self.visit(child)

    def visit_auth_scheme(self, node):
        self.auth_scheme = node.value

    def visit_token68(self, node):
        self.token = node.value

node, _ = rfc7235.Rule("Authorization").parse("Basic YWxhZGRpbjpvcGVuc2VzYW1l", 0)
visitor = AuthVisitor()
visitor.visit(node)

visitor.auth_scheme   # 'Basic'
visitor.token         # 'YWxhZGRpbjpvcGVuc2VzYW1l'
```
