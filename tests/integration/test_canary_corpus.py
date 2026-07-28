"""
Scores the published canary corpus and pins the result.

tests/corpus/canary-corpus.xml carries 46 planted secrets, each a unique
CANARY_* marker. A marker surviving redaction is a leak, so the survivors are
the score, and docs/benchmark.md publishes it.

That file is frozen. It is what ForesightCyber and netgate-xlsx were scored
against, and the published comparison holds only while the denominator does not
move, so markers added later live in canary-corpus-supplementary.xml and are
scored separately.

A published number that nothing enforces drifts. These tests fail in both
directions on purpose:

- a third marker surviving is a redaction regression
- one of the two disappearing means the benchmark doc is now stale

Either way the failure names which marker moved, so the fix is obvious.
"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent
CORPUS = PROJECT_ROOT / 'tests' / 'corpus' / 'canary-corpus.xml'
SUPPLEMENTARY = PROJECT_ROOT / 'tests' / 'corpus' / 'canary-corpus-supplementary.xml'
CANARY_RE = re.compile(r'CANARY_[A-Z0-9_]+')

TOTAL_CANARIES = 46

# The two survivors, and why neither is simply a bug. Kept here rather than as
# a bare set so a failure explains itself without opening the benchmark doc.
EXPECTED_SURVIVORS = {
    'CANARY_WGPUB': (
        'deliberate - a WireGuard *public* key is not a secret, and is in '
        'SECRET_TAG_DENYLIST.'
    ),
    'CANARY_ATTR_PLAIN': (
        'known limitation in this mode - free text in an attribute whose name '
        'is not sensitive. Closed by --redact-descriptions.'
    ),
}

# Closed in 1.2.0 by resolving certificate references against the <refid>
# elements the config declares, rather than assuming any short value in a
# cert-named element is a reference. Listed so a regression names itself.
CLOSED_IN_1_2_0 = ('CANARY_HAPROXYCERTS', 'CANARY_SSLOFFLOAD')


def redact_file(path, *flags):
    """Redact a corpus file to stdout, returning the whole CompletedProcess

    The full result rather than just stdout, because the retained-value warning
    these tests also check is written to stderr.
    """
    result = subprocess.run(
        [sys.executable, '-m', 'pfsense_redactor', str(path), '--stdout', *flags],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT), check=False
    )
    assert result.returncode == 0, f'redaction failed: {result.stderr}'
    return result


def redact_corpus(*flags):
    """Redact the frozen corpus"""
    return redact_file(CORPUS, *flags)


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
        """The denominator in the published score

        Frozen. The other two tools in docs/benchmark.md were scored against
        this exact file, and that table stops meaning anything the moment the
        denominator moves. New markers belong in the supplementary corpus.
        """
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
    """The published headline: 44 of 46 under --aggressive"""

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

    def test_published_score_is_44_of_46(self, aggressive_run):
        """The count of secrets caught, which docs/benchmark.md publishes"""
        caught = TOTAL_CANARIES - len(survivors(aggressive_run))

        assert caught == 44

    @pytest.mark.parametrize('marker', sorted(EXPECTED_SURVIVORS))
    def test_each_survivor_is_accounted_for(self, marker):
        """Every survivor has a recorded reason, so none is an unexplained miss"""
        assert EXPECTED_SURVIVORS[marker].strip()

    @pytest.mark.parametrize('marker', CLOSED_IN_1_2_0)
    def test_certificate_references_stay_closed(self, aggressive_run, marker):
        """These two were survivors until reference resolution landed

        Named individually so a regression in _is_known_cert_reference points
        at itself rather than at a count that moved.
        """
        assert marker not in survivors(aggressive_run)


class TestDescriptionsRaiseTheScore:
    """--redact-descriptions closes the one survivor that is a real gap

    The other is a deliberate choice, so this is as far as the corpus can be
    taken without redacting things that are not secrets.
    """

    def test_score_is_45_of_46(self):
        """The number docs/benchmark.md publishes for this mode"""
        left = survivors(redact_corpus('--aggressive', '--redact-descriptions'))

        assert TOTAL_CANARIES - len(left) == 45

    def test_it_is_the_attribute_marker_that_moves(self):
        """Specifically the free-text attribute, not something else"""
        left = survivors(redact_corpus('--aggressive', '--redact-descriptions'))

        assert 'CANARY_ATTR_PLAIN' not in left
        assert left == set(EXPECTED_SURVIVORS) - {'CANARY_ATTR_PLAIN'}


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


class TestSupplementaryCorpus:
    """Markers added after the benchmark froze, scored on their own

    Kept out of canary-corpus.xml so the published three-tool comparison keeps
    its denominator. Nothing here has been run against the other two tools, so
    nothing here belongs in that table.
    """

    def test_it_exists_and_is_shipped(self):
        """MANIFEST.in ships tests/**.xml, so this reaches the sdist"""
        assert SUPPLEMENTARY.exists(), f'{SUPPLEMENTARY} is missing'

    def test_markers_do_not_overlap_the_frozen_set(self):
        """A duplicated marker would be scored twice and mean neither thing"""
        frozen = set(CANARY_RE.findall(CORPUS.read_text(encoding='utf-8')))
        extra = set(CANARY_RE.findall(SUPPLEMENTARY.read_text(encoding='utf-8')))

        assert not (frozen & extra), (
            'these appear in both corpora: ' + ', '.join(sorted(frozen & extra))
        )

    def test_attribute_blob_is_reported_by_default(self):
        """The 1.2.0 addition: key material in an ordinarily-named attribute

        Retained by default and named in the warning, which is what
        --fail-on-warn gates on. Reporting rather than redacting is deliberate;
        see tests/unit/test_attribute_entropy.py.
        """
        result = redact_file(SUPPLEMENTARY)

        assert 'telemetry[@endpoint_id]' in result.stderr

    def test_aggressive_catches_everything_here(self):
        """No known survivors in this corpus, so any survivor is a regression

        CANARY_ZONEADDR is excluded: it marks an interface name, which is
        structure rather than address and is meant to survive. What must not
        survive is the address beside it, checked below.
        """
        left = survivors(redact_file(SUPPLEMENTARY, '--aggressive')) - {'CANARY_ZONEADDR'}

        assert not left, 'survived --aggressive: ' + ', '.join(sorted(left))

    @pytest.mark.parametrize('flags', [(), ('--aggressive',)])
    def test_bracketed_address_with_a_zone_is_redacted(self, flags):
        """The address in '[addr%zone]:port', which used to pass through whole

        Asserted on the address rather than on the marker, because the marker
        is the zone and the zone is supposed to survive. A test that checked
        only the zone passed for years while the address leaked.
        """
        stdout = redact_file(SUPPLEMENTARY, *flags).stdout

        assert '2001:db8::99' not in stdout, 'bracketed address with a zone leaked'
        assert 'CANARY_ZONEADDR' in stdout, 'the interface name should survive'


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
