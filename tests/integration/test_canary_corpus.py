"""
Scores the published canary corpus and pins the result.

tests/corpus/canary-corpus.xml carries 46 planted secrets, each a unique
CANARY_* marker. A marker surviving redaction is a leak, so the survivors are
the score, and docs/benchmark.md publishes it.

A published number that nothing enforces drifts. These tests fail in both
directions on purpose:

- a fifth marker surviving is a redaction regression
- one of the four disappearing means the benchmark doc is now stale

Either way the failure names which marker moved, so the fix is obvious.
"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent
CORPUS = PROJECT_ROOT / 'tests' / 'corpus' / 'canary-corpus.xml'
CANARY_RE = re.compile(r'CANARY_[A-Z0-9_]+')

TOTAL_CANARIES = 46

# The four survivors, and why each is not simply a bug. Kept here rather than
# as a bare set so a failure explains itself without opening the benchmark doc.
EXPECTED_SURVIVORS = {
    'CANARY_HAPROXYCERTS': (
        'corpus artefact - the marker is a short literal, and short values in '
        'cert-named elements are preserved as references. Real PEM redacts.'
    ),
    'CANARY_SSLOFFLOAD': (
        'corpus artefact - same as CANARY_HAPROXYCERTS.'
    ),
    'CANARY_WGPUB': (
        'deliberate - a WireGuard *public* key is not a secret, and is in '
        'SECRET_TAG_DENYLIST.'
    ),
    'CANARY_ATTR_PLAIN': (
        'known limitation - free text in an attribute whose name is not '
        'sensitive, so SENSITIVE_ATTR_PATTERN does not match it.'
    ),
}


def redact_corpus(*flags):
    """Redact the corpus to stdout, returning the whole CompletedProcess

    The full result rather than just stdout, because the retained-value warning
    these tests also check is written to stderr.
    """
    result = subprocess.run(
        [sys.executable, '-m', 'pfsense_redactor', str(CORPUS), '--stdout', *flags],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT), check=False
    )
    assert result.returncode == 0, f'redaction failed: {result.stderr}'
    return result


def survivors(result):
    """Markers still present in redacted output"""
    return set(CANARY_RE.findall(result.stdout))


# Module-scoped: redacting the corpus is a subprocess spawn, and every test
# below wants one of these same two runs.
@pytest.fixture(scope='module', name='default_run')
def default_run_fixture():
    """The corpus redacted in default mode"""
    return redact_corpus()


@pytest.fixture(scope='module', name='aggressive_run')
def aggressive_run_fixture():
    """The corpus redacted under --aggressive, which the benchmark publishes"""
    return redact_corpus('--aggressive')


class TestCorpusIntegrity:
    """The corpus itself, before any redaction"""

    def test_corpus_exists_and_is_shipped(self):
        """docs/benchmark.md points here, and MANIFEST.in ships tests/**.xml"""
        assert CORPUS.exists(), f'{CORPUS} is missing'

    def test_planted_secret_count(self):
        """The denominator in the published score"""
        planted = set(CANARY_RE.findall(CORPUS.read_text(encoding='utf-8')))

        assert len(planted) == TOTAL_CANARIES

    def test_no_real_addresses(self):
        """Only documentation and private ranges belong in a published fixture

        81.2.69.x was swapped out: it is MaxMind demo data but a genuinely
        assigned range, which has no place in a file this project publishes.
        """
        text = CORPUS.read_text(encoding='utf-8')

        assert '81.2.69.' not in text


class TestAggressiveScore:
    """The published headline: 42 of 46 under --aggressive"""

    def test_exactly_the_known_survivors(self, aggressive_run):
        """Fails in both directions - regression, or a stale benchmark doc"""
        found = survivors(aggressive_run)

        unexpected = found - set(EXPECTED_SURVIVORS)
        assert not unexpected, (
            'redaction regression - these leaked and should not have: '
            + ', '.join(sorted(unexpected))
        )

        fixed = set(EXPECTED_SURVIVORS) - found
        assert not fixed, (
            'these are now redacted, so the score improved. Update '
            'docs/benchmark.md and EXPECTED_SURVIVORS: ' + ', '.join(sorted(fixed))
        )

    def test_published_score_is_42_of_46(self, aggressive_run):
        """The count of secrets caught, which docs/benchmark.md publishes"""
        caught = TOTAL_CANARIES - len(survivors(aggressive_run))

        assert caught == 42

    @pytest.mark.parametrize('marker', sorted(EXPECTED_SURVIVORS))
    def test_each_survivor_is_accounted_for(self, marker):
        """Every survivor has a recorded reason, so none is an unexplained miss"""
        assert EXPECTED_SURVIVORS[marker].strip()


class TestDefaultModeIsNotWorse:
    """Default mode catches less than --aggressive, but must not leak more

    The benchmark is run with --aggressive; this guards the mode most people
    actually use from drifting apart from it unnoticed.
    """

    def test_default_mode_survivors_are_a_superset(self, default_run, aggressive_run):
        """Anything --aggressive leaves, default mode may also leave - not less"""
        default_survivors = survivors(default_run)
        aggressive_survivors = survivors(aggressive_run)

        assert aggressive_survivors <= default_survivors, (
            'aggressive mode leaked something default mode caught, which '
            'inverts the intended relationship between the two'
        )

    def test_default_mode_still_catches_the_core_secrets(self, default_run):
        """A floor, so default mode cannot quietly regress toward doing nothing"""
        caught = TOTAL_CANARIES - len(survivors(default_run))

        assert caught >= 35, f'default mode caught only {caught}/{TOTAL_CANARIES}'


class TestRetainedValuesAreReported:
    """Whatever is not redacted must at least be surfaced for review

    _print_retained_warning is the built-in answer to "what did you leave
    behind", and docs/verifying-output.md tells people to read it.
    """

    def test_high_entropy_retained_is_reported(self, default_run):
        """The warning names the element path, not just a count"""
        assert 'high-entropy' in default_run.stderr
        assert '--aggressive' in default_run.stderr, \
            'the warning should say how to fix it'
