"""Workflow supply-chain properties, asserted rather than reviewed

A pinned action drifts back to a tag the first time someone updates a workflow
without thinking about why the pin was there. These tests are cheap and they
fail loudly, which is the whole point.

They read the workflow files as text. That is deliberate: a YAML parse would
require a dependency this project does not have, and the properties being
asserted are all lexical.
"""
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((PROJECT_ROOT / '.github' / 'workflows').glob('*.yml'))

# `uses: owner/repo@ref` or `uses: owner/repo/path@ref`, ignoring commented-out
# lines so an example in a comment is not treated as a live reference.
USES_RE = re.compile(r'^\s*(?:- )?uses:\s*(\S+)\s*$', re.MULTILINE)
SHA_RE = re.compile(r'@[0-9a-f]{40}$')

# Local composite actions and reusable workflows in this repository have no
# third party to pin against.
LOCAL_PREFIXES = ('./', '.github/')


def code_of(path):
    """A workflow's content with comment-only lines removed

    Every assertion below is about what the workflow *does*. Comments in these
    files explain why a pin is there and what used to be there instead, and
    searching those for the very strings they are explaining finds them.
    """
    return '\n'.join(
        line for line in path.read_text(encoding='utf-8').splitlines()
        if not line.lstrip().startswith('#')
    )


def action_references(path):
    """Every live `uses:` reference in one workflow file"""
    return USES_RE.findall(code_of(path))


@pytest.mark.parametrize('workflow', WORKFLOWS, ids=lambda p: p.name)
class TestActionsArePinned:
    """Every third-party action is pinned to an immutable commit SHA"""

    def test_no_action_is_pinned_to_a_tag_or_branch(self, workflow):
        """A tag is mutable, and a branch is mutable by design

        `ad-m/github-push-action@master` sat in a job holding contents: write
        and GITHUB_TOKEN, which meant whoever controlled that repository's
        master branch could push arbitrary commits here on the next dispatch.
        """
        unpinned = [
            ref for ref in action_references(workflow)
            if not ref.startswith(LOCAL_PREFIXES) and not SHA_RE.search(ref)
        ]

        assert not unpinned, (
            f'{workflow.name} references actions by mutable ref: '
            f'{", ".join(unpinned)}. Pin to a full commit SHA and name the '
            f'release in a comment beside it.'
        )

    def test_every_pin_names_its_release_in_a_comment(self, workflow):
        """A bare SHA is unreviewable; the comment is what makes it readable"""
        lines = workflow.read_text(encoding='utf-8').splitlines()
        missing = [
            line.strip() for index, line in enumerate(lines)
            if SHA_RE.search(line.strip()) and 'uses:' in line
            and not (index and lines[index - 1].strip().startswith('#'))
        ]

        assert not missing, (
            f'{workflow.name}: pinned without a version comment: {missing}'
        )


class TestReleaseAuthentication:
    """OIDC Trusted Publishing is the only way anything reaches PyPI"""

    @pytest.fixture
    def publish_workflow(self):
        """The release workflow, comments removed"""
        path = PROJECT_ROOT / '.github' / 'workflows' / 'python-publish.yml'
        if not path.exists():  # pragma: no cover - repo integrity
            pytest.skip(f'missing workflow: {path}')
        return code_of(path)

    def test_no_workflow_references_a_pypi_token(self):
        """A long-lived token exists between releases and is exposed throughout"""
        offenders = [
            path.name for path in WORKFLOWS if 'PYPI_API_TOKEN' in code_of(path)
        ]

        assert not offenders, (
            f'workflow(s) reference PYPI_API_TOKEN: {offenders}. Trusted '
            f'Publishing through OIDC is the only supported path.'
        )

    def test_the_publish_step_has_no_password_input(self, publish_workflow):
        """A `password:` input is how a token fallback gets reintroduced"""
        assert 'password:' not in publish_workflow

    def test_id_token_write_is_granted_on_the_publish_job_only(self, publish_workflow):
        """The permission that makes OIDC work, scoped as narrowly as it can be"""
        assert 'id-token: write' in publish_workflow

        top_level = publish_workflow.split('jobs:', 1)[0]
        assert 'id-token: write' not in top_level, (
            'id-token: write is granted at the top of the file, so every job '
            'in it can mint a publishing token'
        )


class TestWriteCapableWorkflow:
    """The one workflow that can write to this repository"""

    @pytest.fixture
    def snapshot_workflow(self):
        """The snapshot-update workflow, comments removed"""
        path = PROJECT_ROOT / '.github' / 'workflows' / 'update-snapshots.yml'
        if not path.exists():  # pragma: no cover - repo integrity
            pytest.skip(f'missing workflow: {path}')
        return code_of(path)

    def test_it_runs_no_third_party_action(self, snapshot_workflow):
        """Pinning is a mitigation; running none at all is a removal"""
        third_party = [
            ref for ref in action_references(
                PROJECT_ROOT / '.github' / 'workflows' / 'update-snapshots.yml'
            )
            if not ref.startswith(('actions/', 'github/') + LOCAL_PREFIXES)
        ]

        assert not third_party, (
            f'the write-capable workflow runs third-party action(s): {third_party}'
        )

    def test_write_permission_is_scoped_to_the_job(self, snapshot_workflow):
        """Not granted to the whole file"""
        top_level = snapshot_workflow.split('jobs:', 1)[0]

        assert 'contents: read' in top_level
        assert 'contents: write' not in top_level

    def test_snapshots_are_proposed_rather_than_pushed_to_the_branch(self, snapshot_workflow):
        """A regenerated snapshot becomes the baseline every later run trusts

        One dispatch could otherwise bake a leak into the reference set, and
        every future comparison would then treat it as correct.
        """
        assert 'gh pr create' in snapshot_workflow

    @pytest.mark.parametrize(
        'gate,why',
        [
            ('pytest tests/ -q', 'the suite must pass before and after regeneration'),
            ('BEGIN [A-Z0-9 ]*PRIVATE KEY', 'no private-key marker may reach a snapshot'),
            ('decode_scan.py', 'an encoded marker must not pass a literal grep'),
            ('verifier', 'the snapshots face the same verifier as real output'),
        ],
    )
    def test_it_gates_the_snapshots_before_proposing_them(self, snapshot_workflow, gate, why):
        """Regeneration is exactly the operation that can approve a leak"""
        assert gate in snapshot_workflow, why
