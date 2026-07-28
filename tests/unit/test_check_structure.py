"""
Tests for tools/check_structure.py, the structural CI gate.

A gate that cannot fail is worse than no gate: it reports success while
allowing exactly what it was added to prevent. These check that each rule
actually fires, and that ordinary code passes.
"""
import ast
import importlib.util
from pathlib import Path

import pytest

TOOL_PATH = Path(__file__).parent.parent.parent / 'tools' / 'check_structure.py'


def load_tool():
    """Import check_structure.py, which lives outside the package"""
    spec = importlib.util.spec_from_file_location('check_structure', TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(name='tool')
def tool_fixture():
    """The loaded checker module"""
    return load_tool()


def reasons(tool, source):
    """Run the checker over a source string and return the reasons reported"""
    return [reason for _, _, reason in tool.violations(ast.parse(source))]


class TestNestingDepth:
    """Deeply nested logic is reported"""

    def test_four_deep_is_flagged(self, tool):
        """One level past the limit fires"""
        src = (
            "def f(a, b, c, d):\n"
            "    if a:\n"
            "        for x in b:\n"
            "            while c:\n"
            "                with open(d) as handle:\n"
            "                    return handle\n"
            "    return None\n"
        )

        assert any('nested 4 deep' in r for r in reasons(tool, src))

    def test_three_deep_is_allowed(self, tool):
        """The limit itself passes, so the gate is not off by one"""
        src = (
            "def f(a, b, c):\n"
            "    if a:\n"
            "        for x in b:\n"
            "            if c:\n"
            "                return x\n"
            "    return None\n"
        )

        assert not [r for r in reasons(tool, src) if 'nested' in r]

    def test_nested_function_measured_separately(self, tool):
        """A closure's depth is its own, not added to its parent's

        Otherwise a shallow function containing a shallow closure would report
        as deep, and the fix would be to inline the closure - the opposite of
        what is wanted.
        """
        src = (
            "def outer(a, b):\n"
            "    if a:\n"
            "        def inner(c):\n"
            "            if c:\n"
            "                for x in c:\n"
            "                    return x\n"
            "            return None\n"
            "        return inner\n"
            "    return None\n"
        )

        assert not [r for r in reasons(tool, src) if 'nested' in r]


class TestBumps:
    """Two separate blocks of nested logic in one function are reported"""

    def test_two_nested_blocks_flagged(self, tool):
        """The Bumpy Road shape: two humps doing different things"""
        src = (
            "def f(items, other):\n"
            "    for i in items:\n"
            "        if i:\n"
            "            print(i)\n"
            "    for j in other:\n"
            "        if j:\n"
            "            print(j)\n"
        )

        assert any('blocks of nested logic' in r for r in reasons(tool, src))

    def test_flat_loops_are_not_bumps(self, tool):
        """A loop with no conditional inside is not a hump"""
        src = (
            "def f(items, other):\n"
            "    for i in items:\n"
            "        print(i)\n"
            "    for j in other:\n"
            "        print(j)\n"
        )

        assert not [r for r in reasons(tool, src) if 'blocks' in r]

    def test_elif_branches_count_separately(self, tool):
        """An if/elif chain is one ast.If, but two humps

        Counting the node once read a two-way branch as a single block, so this
        shape passed the gate while CodeScene reported it. _mask_mac_sample was
        the real instance.
        """
        src = (
            "def f(value):\n"
            "    if ':' in value:\n"
            "        parts = value.split(':')\n"
            "        if len(parts) == 6:\n"
            "            return 'a'\n"
            "    elif '.' in value:\n"
            "        parts = value.split('.')\n"
            "        if len(parts) == 3:\n"
            "            return 'b'\n"
            "    return value\n"
        )

        assert any('blocks of nested logic' in r for r in reasons(tool, src))

    def test_else_branch_counts_too(self, tool):
        """The same applies to a plain else, not only to elif"""
        src = (
            "def f(value):\n"
            "    if value:\n"
            "        for i in value:\n"
            "            print(i)\n"
            "    else:\n"
            "        for j in range(3):\n"
            "            print(j)\n"
        )

        assert any('blocks of nested logic' in r for r in reasons(tool, src))

    def test_a_try_contributes_its_body_not_itself(self, tool):
        """Error handling must not hide the humps inside it

        A try wrapping the real work contributed only itself, so a function
        whose whole body sat inside one was measured as a single block.
        _mask_ip_sample was the real instance.
        """
        src = (
            "def f(value):\n"
            "    try:\n"
            "        if value.version == 4:\n"
            "            parts = value.split('.')\n"
            "            if len(parts) == 4:\n"
            "                return 'a'\n"
            "        else:\n"
            "            parts = value.split(':')\n"
            "            if len(parts) >= 3:\n"
            "                return 'b'\n"
            "    except ValueError:\n"
            "        pass\n"
            "    return value\n"
        )

        assert any('blocks of nested logic' in r for r in reasons(tool, src))

    HUMP = (
        "        for {var} in {seq}:\n"
        "            if {var}:\n"
        "                print({var})\n"
    )

    @pytest.mark.parametrize('second_branch', ['except ValueError:', 'finally:'])
    def test_humps_hiding_in_a_try_branch_are_counted(self, tool, second_branch):
        """A handler is the easiest place to hide one

        Measuring `try:` while ignoring `except:` would leave error handling,
        where awkward logic tends to accumulate, entirely unmeasured.
        """
        src = (
            "def f(items, other):\n"
            "    try:\n"
            + self.HUMP.format(var='i', seq='items')
            + f"    {second_branch}\n"
            + self.HUMP.format(var='j', seq='other')
        )

        assert any('blocks of nested logic' in r for r in reasons(tool, src))

    def test_a_hump_in_the_else_branch_is_counted(self, tool):
        """try/except/else, where the else is the interesting half"""
        src = (
            "def f(items, other):\n"
            "    try:\n"
            "        risky()\n"
            "    except ValueError:\n"
            + self.HUMP.format(var='i', seq='items')
            + "    else:\n"
            + self.HUMP.format(var='j', seq='other')
        )

        assert any('blocks of nested logic' in r for r in reasons(tool, src))

    def test_a_plain_handler_is_not_a_hump(self, tool):
        """try/except around one block stays within budget"""
        src = (
            "def f(items):\n"
            "    try:\n"
            "        for i in items:\n"
            "            if i:\n"
            "                print(i)\n"
            "    except ValueError:\n"
            "        pass\n"
        )

        assert not [r for r in reasons(tool, src) if 'blocks' in r]

    def test_dispatching_to_named_helpers_is_clean(self, tool):
        """The shape the two rules above push you toward"""
        src = (
            "def f(self, value):\n"
            "    if ':' in value:\n"
            "        return self._colon(value)\n"
            "    if '.' in value:\n"
            "        return self._dotted(value)\n"
            "    return value\n"
        )

        assert not [r for r in reasons(tool, src) if 'blocks' in r]

    def test_a_single_guarded_block_is_still_allowed(self, tool):
        """One hump is the budget; the rules must not drop it to zero"""
        src = (
            "def f(value):\n"
            "    if value:\n"
            "        for i in value:\n"
            "            print(i)\n"
            "    return value\n"
        )

        assert not [r for r in reasons(tool, src) if 'blocks' in r]


class TestComplexConditional:
    """Conditions chaining several operators are reported"""

    def test_two_operators_flagged(self, tool):
        """'a and b and c' is the shape that has to be re-derived on each read"""
        src = "def f(a, b, c):\n    if a and b and c:\n        return 1\n    return 0\n"

        assert any('chains 2 operators' in r for r in reasons(tool, src))

    def test_one_operator_allowed(self, tool):
        """'a and b' reads directly and stays"""
        src = "def f(a, b):\n    if a and b:\n        return 1\n    return 0\n"

        assert not [r for r in reasons(tool, src) if 'chains' in r]

    def test_nested_boolop_counted_flat(self, tool):
        """Parenthesising does not hide the operator count"""
        src = "def f(a, b, c):\n    if a or (b and c):\n        return 1\n    return 0\n"

        assert any('chains 2 operators' in r for r in reasons(tool, src))

    def test_while_conditions_checked_too(self, tool):
        """Not only if-statements carry conditions"""
        src = "def f(a, b, c):\n    while a and b and c:\n        return 1\n    return 0\n"

        assert any('chains 2 operators' in r for r in reasons(tool, src))


class TestRepositoryIsClean:
    """The gate passes on the tree it is committed with"""

    def test_no_violations_anywhere(self, tool):
        """Every checked path is clean, so a future failure means a regression"""
        root = Path(__file__).parent.parent.parent
        found = []
        for target in ('pfsense_redactor', 'tests', 'tools'):
            for path in sorted((root / target).rglob('*.py')):
                tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
                found += [f"{path.name}:{line} {name}: {reason}"
                          for line, name, reason in tool.violations(tree)]

        assert not found, 'structural violations: ' + '; '.join(found)
