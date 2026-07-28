#!/usr/bin/env python3
"""Fail on the code shapes flake8 cannot see.

`flake8 --select=C901 --max-complexity` already gates cyclomatic complexity,
and mccabe folds a nested closure into its parent, so that part is covered.
What it does not measure at all is *shape*: how deeply logic nests, how many
separate humps of it a function contains, and how many operators a single
condition chains together. Those are exactly the findings this repository set
out to clear, so without a check they would drift straight back.

Thresholds are one step tighter than the analyser that flagged them, so the
first regression trips the gate rather than the second.

Usage:
    python tools/check_structure.py pfsense_redactor/ tests/

Prints `path:line function: reason` for each violation and exits 1, or exits 0
in silence.

Relationship to CodeScene
-------------------------
This gate approximates CodeScene's Bumpy Road rule, and the two agreed only
after `blocks()` was taught about if/elif chains and `try` bodies. On
complexity they still differ in both directions: mccabe scores `redact_text`
and `redact_config` at 8 and CodeScene calls neither complex, while it scored
`_is_secretish_path_segment` at 9 where mccabe said 6. There is no single
number to chase, so the rules here encode shape, which both agree on.

The three functions CodeScene called Complex Method were split rather than
argued with, each into a named predicate or step with the original reasoning
carried across intact:

- `_is_secretish_token` holds the boundary comments that justify the >= 20
  floor and the conditional digit rule; the colon split that catches Telegram
  tokens stays with the segment-level function that does the splitting.
- `_ip_replacement` and `_restore_token_shape` separate choosing a mask from
  putting back the zone id, brackets and port the token arrived with.
- `_merge_allowlist` and `_load_default_allowlists` separate folding one parsed
  triple into the accumulators from deciding which files to read.

Findings deliberately not acted on, so they are not re-opened each time the
dashboard is read:

- **Low Cohesion** and **Number of Functions in a Single Module** on
  redactor.py. Both follow from the single-file design, which that module's
  docstring explains and tests/integration/test_standalone_script.py enforces:
  the file has to run when copied alone to a firewall or jump host. For a tool
  trusted with secrets that guarantee is worth more than a tidier module tree,
  and splitting the file to satisfy a metric would trade it away.

- **Excess Number of Function Arguments** on `PfSenseRedactor.__init__`. Each
  argument is an independent user-facing policy toggle mapped 1:1 to a CLI
  flag; a config object would add indirection without removing a choice. The
  same finding on the traversal methods *was* acted on: redact_ips and
  redact_domains became per-run instance state.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

MAX_NESTING = 3       # if/for/while/try/with inside one another
MAX_BUMPS = 1         # separate nested blocks directly in a function body
MAX_BOOL_OPERATORS = 1  # 'and'/'or' chained in a single condition

NESTING_NODES = (ast.If, ast.For, ast.While, ast.Try, ast.With,
                 ast.AsyncFor, ast.AsyncWith)
FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


def nesting_depth(node: ast.AST, depth: int = 0) -> int:
    """Deepest run of nested blocks, not counting nested function bodies

    A nested function is measured in its own right, so folding its depth into
    the parent would report the same code twice.
    """
    deepest = depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, FUNCTION_NODES):
            continue
        deeper = depth + isinstance(child, NESTING_NODES)
        deepest = max(deepest, nesting_depth(child, deeper))
    return deepest


def count_operands(node: ast.AST) -> int:
    """Leaf operands in a boolean expression, flattening nested and/or"""
    if not isinstance(node, ast.BoolOp):
        return 1
    return sum(count_operands(value) for value in node.values)


def too_deep(func: ast.AST):
    """Report a function whose blocks nest further than the limit"""
    depth = nesting_depth(func)
    if depth > MAX_NESTING:
        yield func.lineno, func.name, f"nested {depth} deep (max {MAX_NESTING})"


def _as_block(body: list) -> ast.AST:
    """Wrap a list of statements so nesting_depth can measure it"""
    return ast.Module(body=body, type_ignores=[])


def _try_branches(stmt: ast.Try) -> list:
    """Every statement list a try can carry: body, each handler, else, finally"""
    branches = [stmt.body, stmt.orelse, stmt.finalbody]
    branches.extend(handler.body for handler in stmt.handlers)
    return [b for b in branches if b]


def _try_blocks(stmt: ast.Try):
    """The blocks inside a try, from whichever branch they sit in"""
    for branch in _try_branches(stmt):
        for inner in branch:
            if isinstance(inner, NESTING_NODES):
                yield from blocks(inner)


def blocks(stmt: ast.AST):
    """Yield each separately-reachable block of logic within a statement

    Two shapes hide bumps from a naive count of `func.body`, and both were
    found by comparing this tool against CodeScene's Bumpy Road rule, which
    reported functions this gate had passed:

    - An `if/elif/else` chain is a *single* ast.If, with each `elif` buried in
      the previous branch's orelse. Counting the node once reads a three-way
      branch as one block.
    - A `try` wrapping the real work contributes only itself, so everything
      inside it is invisible.

    Every branch of a `try` counts, not just its body. A handler is where the
    awkward logic tends to accumulate, so measuring `try:` while ignoring
    `except:` would leave the easiest place to hide a hump unmeasured.

    Anything else is its own single block.
    """
    if isinstance(stmt, ast.Try):
        yield from _try_blocks(stmt)
        return

    if not isinstance(stmt, ast.If):
        yield stmt
        return

    yield _as_block(stmt.body)
    orelse = stmt.orelse
    while len(orelse) == 1 and isinstance(orelse[0], ast.If):
        yield _as_block(orelse[0].body)
        orelse = orelse[0].orelse
    if orelse:
        yield _as_block(orelse)


def too_bumpy(func: ast.AST):
    """Report a function carrying several separate blocks of nested logic

    A bump is a top-level block that itself contains nested logic. A flat loop
    is not one; a loop wrapping a conditional is. Two of them in one function
    means two things are going on in it.

    Branches of an if/elif chain count separately, and a try contributes its
    body rather than itself - see blocks() for why.
    """
    bumps = sum(1 for stmt in func.body if isinstance(stmt, NESTING_NODES)
                for block in blocks(stmt) if nesting_depth(block) >= 1)
    if bumps > MAX_BUMPS:
        yield func.lineno, func.name, f"{bumps} blocks of nested logic (max {MAX_BUMPS})"


def chained_conditions(func: ast.AST):
    """Report each condition joining more operators than the limit allows"""
    for node in ast.walk(func):
        test = getattr(node, 'test', None)
        if not isinstance(test, ast.BoolOp):
            continue
        operators = count_operands(test) - 1
        if operators > MAX_BOOL_OPERATORS:
            yield (test.lineno, func.name,
                   f"condition chains {operators} operators "
                   f"(max {MAX_BOOL_OPERATORS}) - name it instead")


RULES = (too_deep, too_bumpy, chained_conditions)


def violations(tree: ast.AST):
    """Yield (line, function, reason) for every shape over threshold

    One function per rule, rather than three blocks in a loop. The tool that
    gates complexity is a poor advertisement for it otherwise - this function
    was itself the worst in the repository until it was split.
    """
    for func in (n for n in ast.walk(tree) if isinstance(n, FUNCTION_NODES)):
        for rule in RULES:
            yield from rule(func)


def python_files(targets: list[str]):
    """Expand each argument into the .py files under it"""
    for target in targets:
        path = Path(target)
        if path.is_dir():
            yield from sorted(path.rglob('*.py'))
        elif path.suffix == '.py':
            yield path


def main() -> int:
    """Report every violation across the given paths. Non-zero means failure"""
    targets = sys.argv[1:] or ['pfsense_redactor', 'tests']
    found = 0

    for path in python_files(targets):
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        except SyntaxError as exc:
            print(f"{path}:{exc.lineno} could not parse: {exc.msg}")
            found += 1
            continue

        # Sorted so the report is stable regardless of walk order.
        for line, name, reason in sorted(violations(tree)):
            print(f"{path}:{line} {name}: {reason}")
            found += 1

    if found:
        print(f"\n{found} structural violation(s). "
              f"Extracting a named function is the usual fix.")
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main())
