"""Independent verification of redacted output

The redactor is a single transformation pass. Everything it does rests on one
set of judgements - is this element name a secret, is this value shaped like
one - and until this module existed, the only "verification" was the
transformer reporting what it had chosen to keep. A class of secret the
transformer cannot see was equally invisible to the check, which is the
correlated-failure problem in its strongest form: not a verifier that shares the
transformer's patterns, but no verifier at all.

This module re-reads the **serialised candidate output** and looks for material
that should not be in it. Two strategies, deliberately different in kind:

**A. Shape scan.** Patterns defined here, not imported from the transformer.
They overlap in intent - both look for PEM headers - but they are written and
maintained separately, so a mistake in one is not automatically a mistake in
the other. This catches what the transformer's rules do not cover.

**B. Input-value retention.** Every leaf and attribute value in the *input*
above a minimum length is checked for verbatim survival in the output. This is
the one check that cannot inherit the transformer's blind spots, because it does
not classify anything: it does not need to know what a value means to notice
that it came out unchanged.

Findings carry a path, a category, a length and a reason. They never carry the
value, a prefix of it, or a hash of it - a short secret's hash is
brute-forceable, and a prefix is often the whole of what identifies a token's
issuer. A finding exists to tell an operator where to look, not to reproduce
what was found.

Kept in its own module so that it can be read, reviewed and changed
independently of the 3,500 lines it is checking. redactor.py imports it
tolerantly (see _load_verifier there): when the module is absent - the
single-file deployment the project supports - verification is reported as
unavailable rather than silently skipped, and the modes that depend on it
refuse to run.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Iterator

# ==========================================================================
# Bounds
# ==========================================================================
# The verifier runs over output the transformer has already produced, so it is
# not the first thing to see hostile input - but it is the last, and a verifier
# that can be made to hang is a verifier that can be removed from the pipeline.
MAX_DECODE_DEPTH: int = 3
MAX_DECODED_BYTES: int = 65536
MAX_DECODE_OPERATIONS: int = 64
MIN_ENCODED_RUN_CHARS: int = 24
MAX_ENCODED_RUN_CHARS: int = (MAX_DECODED_BYTES * 4) // 3 + 4

# Values shorter than this are not compared for verbatim retention. Below 16
# characters the comparison stops distinguishing a surviving secret from a
# coincidence: 'admin', 'lan', 'yes' and '1194' all appear in both input and
# output of a correctly redacted file, and reporting them buries the finding
# that matters.
MIN_RETENTION_LENGTH: int = 16

# Ceiling on the number of distinct input values tracked, so a pathological
# document cannot make the verifier the memory problem.
MAX_TRACKED_VALUES: int = 20000

# Ceiling on findings returned. A run that produces this many has a systemic
# problem, and the operator needs the first few, not all of them.
MAX_FINDINGS: int = 200

# ==========================================================================
# Shape patterns - defined here, not imported from the transformer
# ==========================================================================
VERIFIER_PRIVATE_KEY_RE = re.compile(
    r'-----BEGIN[ \t]+(?:[A-Za-z0-9]+[ \t]+){0,4}PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?[ \t]*-----'
    r'|-----BEGIN[ \t]+OPENVPN[ \t]+STATIC[ \t]+KEY(?:[ \t]+V\d)?[ \t]*-----',
    re.IGNORECASE
)

VERIFIER_JWT_RE = re.compile(
    r'eyJ[A-Za-z0-9_-]{5,8192}\.[A-Za-z0-9_-]{4,8192}\.[A-Za-z0-9_-]{0,8192}'
)

# A credential inside a URL. Matched on the userinfo separator rather than on
# any scheme list, so a scheme the transformer does not know about is still
# caught. The password component is captured so that a URL whose password has
# already been replaced is not reported as still carrying one - reporting the
# redaction as the leak is the one way a verifier can be worse than useless.
VERIFIER_URL_CREDENTIAL_RE = re.compile(
    r'[A-Za-z][A-Za-z0-9+.\-]{1,32}://[^\s/@:]{1,256}:(?P<secret>[^\s/@]{1,256})@'
)

# Long opaque runs. Deliberately looser than the transformer's rule: the
# verifier's job is to raise a question, not to decide the answer.
VERIFIER_HEX_RE = re.compile(r'(?<![0-9A-Fa-f])[0-9A-Fa-f]{40,}(?![0-9A-Fa-f])')
VERIFIER_BASE64_RE = re.compile(r'(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{48,}(?![A-Za-z0-9+/=_-])')

_ENCODED_RUN_RE = re.compile(r'[A-Za-z0-9+/=_-]{%d,}' % MIN_ENCODED_RUN_CHARS)
_URLSAFE_TO_STANDARD = str.maketrans('-_', '+/')

_UUID_RE = re.compile(
    r'\A[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-'
    r'[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\Z'
)

# Entropy floor for the opaque-run scan. Higher than the transformer's, because
# a finding here costs an operator an investigation and the shape rule is
# looser to begin with.
MIN_RUN_ENTROPY_BITS: float = 3.0

# Placeholders this project writes. A finding naming one of these would be the
# verifier reporting the redaction as the leak.
PLACEHOLDER_VALUES: frozenset[str] = frozenset({
    '[REDACTED]', '[REDACTED_CERT_OR_KEY]', '[REDACTED_OVERSIZED]',
    'XX:XX:XX:XX:XX:XX', 'XXXX.XXXX.XXXX', 'XXX.XXX.XXX.XXX',
})

# Inside URL userinfo the placeholder is written without brackets, because
# square brackets are not safe there. Kept as its own set rather than folded
# into the one above, so 'REDACTED' is only ever accepted as a placeholder in
# the position where the tool actually writes it.
URL_USERINFO_PLACEHOLDERS: frozenset[str] = frozenset({
    'REDACTED', '[REDACTED]',
})

# The alphabet a credential actually arrives in.
#
# Base64, Base64URL, hex, pre-shared keys and API keys are all subsets of this
# set. A value containing anything else - a dot, a colon, a comma, a question
# mark, an at-sign - is a path, a URL, a hostname, an email or a delimited list.
#
# This is the retention comparison's one concession to form, and it is what
# makes the check usable rather than a wall of noise: without it, every
# firewall-rule description, cron command and package metadata field in a real
# config is reported, and a report nobody can read is a report nobody reads.
#
# It is a stated limitation, not a claim of completeness. A secret carrying a
# dot is invisible to *this* check - and is covered instead by the shape scan,
# which looks for JWTs and credential-bearing URLs specifically.
CREDENTIAL_ALPHABET_RE = re.compile(r'\A[A-Za-z0-9+/=_-]+\Z')

# Structural values that legitimately appear unchanged in the output and are
# not secrets. Narrow and testable by design: every entry is a fact about
# pfSense's schema rather than a guess about content.
#
# Element names whose values are structural identifiers or enumerations. A
# refid is the reference the 1.2.0 work exists to preserve; a UUID is an object
# identifier; an interface name is how the config is read at all.
STRUCTURAL_ELEMENTS: frozenset[str] = frozenset({
    'refid', 'uuid', 'if', 'interface', 'interfaces', 'type', 'protocol',
    'proto', 'version', 'descr_type', 'mode', 'state', 'status',
    'cipher', 'digest', 'hash-algorithm', 'dhgroup', 'ealgo', 'halgo',
    'encryption-algorithm-option', 'hash-algorithm-option',
    'crypto', 'keylen', 'certref', 'caref', 'sslcertref',
    # Package metadata: what a package is called, which file configures it and
    # which function builds its rules. All of it is public knowledge about the
    # package rather than anything about this firewall.
    'priv', 'internal_name', 'configurationfile', 'filter_rule_function',
    'include_file', 'pkginfolink', 'sequence', 'associated-rule-id',
    'pkg_repo_conf_path', 'pkg_repo_conf_branch',
})


# ==========================================================================
# Result types
# ==========================================================================
@dataclass(frozen=True)
class VerificationFinding:
    """One reason the candidate output should not be distributed

    Metadata only. `path` locates the value, `kind` says what it looked like,
    `length` says how much of it there was, and `reason` says which check
    raised it. The value itself is deliberately absent: this object is written
    to JSON reports and printed to logs, both of which are shared.
    """

    finding_id: str
    path: str
    kind: str
    length: int
    reason: str


@dataclass(frozen=True)
class VerificationResult:
    """The verdict on one candidate document

    `clean` is the only thing a caller should gate on. An empty `findings`
    tuple and `clean` being True are the same statement, kept as two fields so
    that a caller reading `result.clean` cannot get the polarity wrong.
    """

    clean: bool
    findings: tuple[VerificationFinding, ...]

    @property
    def count(self) -> int:
        """How many findings there are"""
        return len(self.findings)


def build_result(findings: Iterable[VerificationFinding]) -> VerificationResult:
    """Build a result, bounded and with a deterministic order

    Deduplicated on the whole finding, so the same retained value reached by
    two checks is reported once. Ordered so that two runs over the same
    document produce the same report, which is what makes a report diffable.
    """
    ordered = sorted(set(findings), key=lambda f: (f.finding_id, f.path, f.length))
    return VerificationResult(clean=not ordered, findings=tuple(ordered[:MAX_FINDINGS]))


# Retained for readability at the call sites inside this module.
_result = build_result


# ==========================================================================
# Bounded decoding - the verifier's own, not the transformer's
# ==========================================================================
def _decode_run(run: str) -> str | None:
    """Decode one Base64 or Base64URL run, or None"""
    if len(run) > MAX_ENCODED_RUN_CHARS:
        return None

    body = run.rstrip('=')
    padded = body + '=' * (-len(body) % 4)
    for candidate in (padded, padded.translate(_URLSAFE_TO_STANDARD)):
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        if decoded and len(decoded) <= MAX_DECODED_BYTES:
            return decoded.decode('utf-8', errors='replace')
    return None


def _decode_layer(text: str, budget: int) -> tuple[list[str], int]:
    """Decode every encoded run in one layer, spending a shared budget"""
    produced: list[str] = []
    for run in _ENCODED_RUN_RE.findall(text):
        if budget <= 0:
            break
        budget -= 1
        decoded = _decode_run(run)
        if decoded is not None:
            produced.append(decoded)
    return produced, budget


def decoded_layers(text: str) -> list[str]:
    """Bounded successive decodings of `text`, excluding `text` itself

    Never returns, logs or stores the decoded content anywhere a caller could
    accidentally publish it: callers scan it and discard it.
    """
    layers: list[str] = []
    frontier = [text]
    seen = {text}
    budget = MAX_DECODE_OPERATIONS

    for _ in range(MAX_DECODE_DEPTH):
        produced: list[str] = []
        for layer in frontier:
            decoded, budget = _decode_layer(layer, budget)
            produced.extend(item for item in decoded if item not in seen)
            seen.update(decoded)

        layers.extend(produced)
        frontier = produced
        if not frontier or budget <= 0:
            break

    return layers


def _entropy_bits(value: str) -> float:
    """Shannon entropy of `value` in bits per character"""
    if not value:
        return 0.0
    total = len(value)
    return -sum(
        (n / total) * math.log2(n / total) for n in Counter(value).values()
    )


# ==========================================================================
# Strategy A: shape scan over the serialised candidate
# ==========================================================================
def _shape_findings_in(text: str, where: str, depth: int) -> Iterator[VerificationFinding]:
    """Unambiguous credential structures in one layer of text"""
    suffix = '' if depth == 0 else f' (decoded, depth {depth})'

    for match in VERIFIER_PRIVATE_KEY_RE.finditer(text):
        yield VerificationFinding(
            finding_id='retained-private-key', path=where, kind='pem-private-key',
            length=len(match.group(0)),
            reason=f'private-key PEM header in candidate output{suffix}',
        )

    for match in VERIFIER_JWT_RE.finditer(text):
        yield VerificationFinding(
            finding_id='retained-jwt', path=where, kind='jwt',
            length=len(match.group(0)),
            reason=f'compact JWT in candidate output{suffix}',
        )

    for match in VERIFIER_URL_CREDENTIAL_RE.finditer(text):
        if match.group('secret') in URL_USERINFO_PLACEHOLDERS:
            continue
        yield VerificationFinding(
            finding_id='retained-url-credential', path=where, kind='url-userinfo',
            length=len(match.group(0)),
            reason=f'credential in URL userinfo in candidate output{suffix}',
        )


def _opaque_run_findings(text: str, where: str) -> Iterator[VerificationFinding]:
    """Long hexadecimal and Base64 runs that nothing accounted for"""
    for pattern, kind in ((VERIFIER_HEX_RE, 'hex-run'), (VERIFIER_BASE64_RE, 'base64-run')):
        for match in pattern.finditer(text):
            run = match.group(0)
            if _is_accounted_for(run):
                continue
            yield VerificationFinding(
                finding_id='retained-opaque-run', path=where, kind=kind,
                length=len(run),
                reason='long opaque run in candidate output',
            )


def _is_accounted_for(run: str) -> bool:
    """Whether a long run is something other than an unexplained secret"""
    if run in PLACEHOLDER_VALUES:
        return True
    if _UUID_RE.match(run):
        return True
    return _entropy_bits(run) < MIN_RUN_ENTROPY_BITS


def scan_shapes(candidate: str) -> VerificationResult:
    """Strategy A: what the serialised output looks like, on its own terms

    Runs over the whole document rather than element by element, so material
    split across an element boundary or hidden in a comment is still seen. The
    path reported is the document, because at this level there is no smaller
    one to give without re-parsing - and re-parsing would inherit the reader
    the transformer used.
    """
    findings = list(_shape_findings_in(candidate, 'document', depth=0))
    findings.extend(_opaque_run_findings(candidate, 'document'))

    for depth, layer in enumerate(decoded_layers(candidate), start=1):
        findings.extend(_shape_findings_in(layer, 'document', depth=depth))

    return _result(findings)


# ==========================================================================
# Strategy B: verbatim retention of input values
# ==========================================================================
@dataclass(frozen=True)
class TrackedValue:
    """One input value worth checking for verbatim survival"""

    path: str
    value: str
    kind: str


def _element_path(stack: list[str], tag: str) -> str:
    """Slash-joined path for an element, matching the transformer's format"""
    return '/'.join([*stack, tag])


def _normalise_tag(tag: str) -> str:
    """Strip any namespace and lower-case, as the transformer does"""
    return tag.rsplit('}', 1)[-1].lower()


def _is_excluded(tag: str, value: str, allowlisted: frozenset[str]) -> bool:
    """Whether an input value is expected to survive unchanged

    Every exclusion is narrow and stated as a fact about the schema, about the
    shape of the value, or about what the operator asked for - never as a guess
    about what the value means:

    - the tool's own placeholders, so redaction is not reported as a leak
    - explicit allow-list entries, which the operator asked to keep
    - structural elements whose values are references, identifiers or
      enumerations: the things a reader needs in order to follow the config
    - absolute filesystem paths, which pfSense stores in quantity and which the
      transformer deliberately preserves - a corrupted path helps nobody
    - anything outside CREDENTIAL_ALPHABET_RE; see that constant for why, and
      for what it therefore does not see

    Each of these is asserted individually in
    tests/unit/test_output_verification.py, so the set cannot quietly widen.
    """
    if value in PLACEHOLDER_VALUES:
        return True
    if value.lower() in allowlisted:
        return True
    if tag in STRUCTURAL_ELEMENTS:
        return True
    if value.startswith('/'):
        return True
    return not CREDENTIAL_ALPHABET_RE.match(value)


def collect_input_values(
    root: ET.Element,
    allowlisted: frozenset[str] = frozenset(),
    min_length: int = MIN_RETENTION_LENGTH,
) -> list[TrackedValue]:
    """Every input leaf and attribute value long enough to be worth checking

    Bounded by MAX_TRACKED_VALUES. Deduplicated on the value, keeping the first
    path it appeared at, so a value repeated across a hundred rules produces one
    finding rather than a hundred identical ones.
    """
    tracked: dict[str, TrackedValue] = {}
    _walk_for_values(root, [], tracked, allowlisted, min_length)
    return list(tracked.values())


def _walk_for_values(
    element: ET.Element,
    stack: list[str],
    tracked: dict[str, TrackedValue],
    allowlisted: frozenset[str],
    min_length: int,
) -> None:
    """Recursive half of collect_input_values

    Depth is bounded by the caller: redactor.py refuses documents deeper than
    its own limit before this ever runs.
    """
    if len(tracked) >= MAX_TRACKED_VALUES:
        return

    tag = _normalise_tag(element.tag)
    _track_element_value(element, stack, tag, tracked, allowlisted, min_length)
    _track_attribute_values(element, stack, tag, tracked, allowlisted, min_length)

    stack.append(tag)
    try:
        for child in element:
            _walk_for_values(child, stack, tracked, allowlisted, min_length)
    finally:
        stack.pop()


def _track_element_value(
    element: ET.Element, stack: list[str], tag: str,
    tracked: dict[str, TrackedValue], allowlisted: frozenset[str], min_length: int,
) -> None:
    """Record this element's own text if it is worth checking"""
    value = (element.text or '').strip()
    if len(value) < min_length:
        return
    if _is_excluded(tag, value, allowlisted):
        return
    tracked.setdefault(value, TrackedValue(_element_path(stack, tag), value, 'element'))


def _track_attribute_values(
    element: ET.Element, stack: list[str], tag: str,
    tracked: dict[str, TrackedValue], allowlisted: frozenset[str], min_length: int,
) -> None:
    """Record this element's attribute values if they are worth checking"""
    for name, raw in element.attrib.items():
        value = raw.strip()
        if len(value) < min_length:
            continue
        if _is_excluded(name.lower(), value, allowlisted):
            continue
        path = f'{_element_path(stack, tag)}[@{name.lower()}]'
        tracked.setdefault(value, TrackedValue(path, value, 'attribute'))


def scan_retention(
    tracked: Iterable[TrackedValue], candidate: str
) -> VerificationResult:
    """Strategy B: which input values came out the other side unchanged

    The check that cannot inherit the transformer's blind spots, because it
    classifies nothing. It does not need to know what a value means in order to
    notice that it survived.

    Whitespace is collapsed before comparison so that a value the serialiser
    re-wrapped is still recognised as the same value.
    """
    haystack = _collapse(candidate)
    findings = [
        VerificationFinding(
            finding_id='retained-input-value',
            path=item.path,
            kind=item.kind,
            length=len(item.value),
            reason='input value present verbatim in candidate output',
        )
        for item in tracked
        if _collapse(item.value) in haystack
    ]
    return _result(findings)


def _collapse(text: str) -> str:
    """Remove whitespace, so re-wrapping does not defeat a comparison"""
    return ''.join(text.split())


# ==========================================================================
# Entry point
# ==========================================================================
def verify_candidate(
    candidate: str,
    input_root: ET.Element | None = None,
    allowlisted: frozenset[str] = frozenset(),
) -> VerificationResult:
    """Verify one serialised candidate document

    `candidate` is the exact text that would be written or emitted. Verifying
    anything else - the tree, the transformer's statistics, a summary - would
    verify something other than what the operator ends up sharing.

    `input_root` enables the retention comparison. Without it only the shape
    scan runs, which is weaker: pass the parsed input whenever it is available.
    """
    findings = list(scan_shapes(candidate).findings)

    if input_root is not None:
        tracked = collect_input_values(input_root, allowlisted)
        findings.extend(scan_retention(tracked, candidate).findings)

    return _result(findings)


def describe(result: VerificationResult, limit: int = 10) -> list[str]:
    """One human-readable line per finding, safe to print or log

    Built from the finding's metadata only, so a caller cannot print a secret
    by printing a finding.
    """
    lines = [
        f'{finding.finding_id}: {finding.path} '
        f'({finding.kind}, {finding.length} chars) - {finding.reason}'
        for finding in result.findings[:limit]
    ]
    if result.count > limit:
        lines.append(f'... and {result.count - limit} more')
    return lines
