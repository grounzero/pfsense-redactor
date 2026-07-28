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


def violations(tree: ast.AST):
    """Yield (line, function, reason) for every shape over threshold"""
    for func in (n for n in ast.walk(tree) if isinstance(n, FUNCTION_NODES)):
        depth = nesting_depth(func)
        if depth > MAX_NESTING:
            yield func.lineno, func.name, f"nested {depth} deep (max {MAX_NESTING})"

        # A bump is a top-level block that itself contains nested logic. A flat
        # loop is not one; a loop wrapping a conditional is. Two of them in one
        # function means two things are going on in it.
        bumps = sum(1 for stmt in func.body
                    if isinstance(stmt, NESTING_NODES) and nesting_depth(stmt) >= 1)
        if bumps > MAX_BUMPS:
            yield func.lineno, func.name, f"{bumps} blocks of nested logic (max {MAX_BUMPS})"

        for node in ast.walk(func):
            test = getattr(node, 'test', None)
            if not isinstance(test, ast.BoolOp):
                continue
            operators = count_operands(test) - 1
            if operators > MAX_BOOL_OPERATORS:
                yield (test.lineno, func.name,
                       f"condition chains {operators} operators "
                       f"(max {MAX_BOOL_OPERATORS}) - name it instead")


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
