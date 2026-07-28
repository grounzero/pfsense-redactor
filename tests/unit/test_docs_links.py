"""
Tests for documentation links.

Splitting the README into docs/ broke a relative link on the first attempt:
`allowlist.example` resolved from the repository root, but not from inside
docs/. Nothing caught it but a manual check, so these tests exist.

They also pin the two rules that are easy to violate without noticing:

- the README is the PyPI long_description, and PyPI does not resolve relative
  Markdown links, so links out of the README must be absolute
- every docs page needs a way back to the index, or arriving from a search
  result is a dead end
"""
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent
DOCS_DIR = PROJECT_ROOT / 'docs'
README = PROJECT_ROOT / 'README.md'

# [text](target) where target is not a URL and not a bare #anchor
RELATIVE_LINK_RE = re.compile(r'\]\((?!https?://|mailto:|#)([^)#]+)(?:#[^)]*)?\)')
BREADCRUMB = '[← Documentation index](../README.md#documentation)'

DOC_PAGES = sorted(DOCS_DIR.glob('*.md'))


def relative_links(path):
    """Every relative link target in a Markdown file"""
    return RELATIVE_LINK_RE.findall(path.read_text(encoding='utf-8'))


def headings(path):
    """Heading lines, ignoring fenced code blocks

    Shell examples are full of '# comment' lines. Counting those as headings
    reports five H1s in a file that has one.
    """
    found, in_fence = [], False
    for line in path.read_text(encoding='utf-8').splitlines():
        if line.startswith('```'):
            in_fence = not in_fence
            continue
        if not in_fence and re.match(r'^#{1,6} ', line):
            found.append(line)
    return found


@pytest.mark.parametrize('page', DOC_PAGES, ids=lambda p: p.name)
class TestDocPages:
    """Rules every page under docs/ must satisfy"""

    def test_relative_links_resolve(self, page):
        """A link to a file that is not there is worse than no link"""
        broken = [
            target for target in relative_links(page)
            if not (page.parent / target).resolve().exists()
        ]

        assert not broken, f'{page.name} links to missing: {", ".join(broken)}'

    def test_has_breadcrumb_back_to_index(self, page):
        """Arriving from a search result should not be a dead end"""
        head = page.read_text(encoding='utf-8').split('\n\n')[:3]

        assert any(BREADCRUMB in part for part in head), (
            f'{page.name} has no link back to the documentation index'
        )

    def test_starts_with_a_single_h1(self, page):
        """One title per page, and it comes first"""
        found = headings(page)
        h1s = [line for line in found if line.startswith('# ')]

        assert found[0].startswith('# '), f'{page.name} does not open with an H1'
        assert len(h1s) == 1, f'{page.name} has {len(h1s)} H1 headings'

    def test_heading_levels_do_not_skip(self, page):
        """H1 straight to H3 reads as a missing section

        Removing the duplicate H2s during review left orphaned H3s behind, so
        this is a mistake already made once.
        """
        levels = [len(line.split(' ', 1)[0]) for line in headings(page)]
        skips = [(a, b) for a, b in zip(levels, levels[1:]) if b > a + 1]

        assert not skips, f'{page.name} skips heading levels: {skips}'


class TestReadme:
    """The README is also the PyPI package page, which constrains its links"""

    def test_no_relative_links_to_docs(self):
        """PyPI does not resolve relative Markdown links

        A relative docs/ link renders as a broken link on the package page,
        which is the first thing many people see.
        """
        content = README.read_text(encoding='utf-8')

        assert '](docs/' not in content, (
            'README links to docs/ relatively; use the full GitHub URL so the '
            'link works on PyPI as well'
        )

    def test_every_doc_page_is_listed(self):
        """A page nothing links to is a page nobody finds"""
        content = README.read_text(encoding='utf-8')
        unlisted = [p.name for p in DOC_PAGES if f'docs/{p.name}' not in content]

        assert not unlisted, f'not linked from README: {", ".join(unlisted)}'

    def test_documentation_anchor_exists(self):
        """Every breadcrumb points at this heading, so it must be there"""
        content = README.read_text(encoding='utf-8')

        assert re.search(r'^## Documentation$', content, re.MULTILINE)
