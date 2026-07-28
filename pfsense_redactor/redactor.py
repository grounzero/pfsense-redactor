"""
pfSense XML Configuration Redactor
Redacts sensitive information from pfSense config.xml files

Single-module design
--------------------
This file is large and deliberately stays that way. It must remain runnable as
a lone file - copied on its own to a firewall or jump host, with no package
context and nothing else beside it:

    python3 redactor.py config.xml --stdout

For a tool whose job is to be trusted with secrets, "read this one file, then
run it" is worth more than a tidier module tree. Any relative or sibling import
would end that, so there are none that are required; the two optional ones -
the __version__ lookup in resolve_version() and the verifier in
_load_verifier() - both fall back cleanly.

Guarded by tests/integration/test_standalone_script.py, and by the C0302
disable in .pylintrc.

The independent verifier
------------------------
verifier.py is a separate module on purpose. It re-reads the serialised output
looking for material that should not be in it, using rules written and
maintained apart from the ones here - a verifier that shares the transformer's
assumptions cannot catch the transformer's mistakes.

That makes it the one thing this file will not inline. Copied out alone,
redactor.py still redacts, but it reports verification as **unavailable**
rather than pretending it passed. Copy verifier.py alongside it to keep the
assurance the package build gives you.

Layout
------
Sections below are marked with banner comments, in this order:

    1. Logging          ColouredFormatter, setup_logging
    2. Constants        element sets, secret/cert tag patterns, deny-list
    3. Version          resolve_version
    4. Verification     _load_verifier and the candidate-verification API
    5. Redactor         PfSenseRedactor - the bulk of the file
    6. Allowlists       allow-list file parsing
    7. Path safety      path traversal / sensitive directory validation
    8. CLI              argparse wiring and main()
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
import argparse
import base64
import binascii
import math
import re
import sys
import ipaddress
import functools
import logging
from pathlib import Path
from collections import Counter, defaultdict
from collections.abc import Callable
from itertools import islice
from typing import NoReturn, Union
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, SplitResult
import os

# Type aliases (using Union for Python 3.9 compatibility)
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


# ==========================================================================
# 1. LOGGING
# ==========================================================================
class ColouredFormatter(logging.Formatter):
    """Add ANSI colour codes to log messages for TTY output"""

    # ANSI colour codes
    COLOURS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'RESET': '\033[0m'      # Reset
    }

    def __init__(self, fmt=None, datefmt=None, style='%', stream=None):
        """Initialise formatter with optional stream for TTY detection"""
        super().__init__(fmt, datefmt, style)
        self.stream = stream

    @staticmethod
    def _stream_is_tty(stream) -> bool:
        """Whether the stream is a terminal that can render colour

        Streams reaching here are not always file objects - the tests pass
        stand-ins - so isatty is checked for rather than assumed.
        """
        return bool(stream) and hasattr(stream, 'isatty') and stream.isatty()

    def format(self, record):
        """Format log record with colours if outputting to a TTY

        Note: We colour the final formatted string rather than mutating
        the record to avoid issues with multiple handlers.
        """
        # Get the formatted message without colours
        formatted = super().format(record)

        # Only add colours if outputting to a TTY
        if self._stream_is_tty(self.stream):
            levelname = record.levelname
            if levelname in self.COLOURS:
                colour = self.COLOURS[levelname]
                reset = self.COLOURS['RESET']
                # Colour the entire formatted message
                formatted = f"{colour}{formatted}{reset}"

        return formatted


def setup_logging(level: int = logging.INFO, use_stderr: bool = False) -> logging.Logger:
    """Configure logging for pfSense redactor

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        use_stderr: If True, route all logs to stderr (for --stdout mode)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('pfsense_redactor')
    logger.setLevel(level)
    logger.handlers.clear()  # Remove any existing handlers
    logger.propagate = False  # Prevent propagation to root logger

    if use_stderr:
        # In --stdout mode, route everything to stderr
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(level)
        handler.setFormatter(ColouredFormatter('%(message)s', stream=sys.stderr))
        logger.addHandler(handler)
    else:
        # Normal mode: INFO/DEBUG to stdout, WARNING/ERROR to stderr
        # Handler for INFO and DEBUG messages -> stdout
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setLevel(logging.DEBUG)
        stdout_handler.addFilter(lambda record: record.levelno < logging.WARNING)
        stdout_handler.setFormatter(ColouredFormatter('%(message)s', stream=sys.stdout))
        logger.addHandler(stdout_handler)

        # Handler for WARNING and ERROR messages -> stderr
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.WARNING)
        stderr_handler.setFormatter(ColouredFormatter('%(message)s', stream=sys.stderr))
        logger.addHandler(stderr_handler)

    return logger


# Module-level constants (immutable for safety)
# ==========================================================================
# 2. CONSTANTS - element sets, secret/cert tag patterns, deny-list
# ==========================================================================
ALWAYS_PRESERVE_IPS: frozenset[str] = frozenset({
    '255.255.255.0', '255.255.0.0', '255.0.0.0',
    '255.255.255.128', '255.255.255.192', '255.255.255.224',
    '255.255.255.240', '255.255.255.248', '255.255.255.252',
    '255.255.255.254', '255.255.255.255',
    '0.0.0.0', '::'
})

REDACT_ELEMENTS: frozenset[str] = frozenset({
    'password', 'passwordenc', 'bcrypt-hash', 'md5-hash', 'nt-hash',
    'pre-shared-key', 'shared_key', 'psk', 'privatekey',
    'prv',  # Private keys are secrets, not just certs
    'secret', 'community',  # SNMP community strings
    'apikey', 'api_key', 'auth_key', 'priv_key',
    'encryption_password', 'radius_secret', 'ipsec_psk', 'ldap_bindpw',
    'tls', 'tlsauth', 'tls-crypt', 'static_key', 'private-key',
    # Note: 'key' handled specially - can be short secret or PEM blob
})

CERT_KEY_ELEMENTS: frozenset[str] = frozenset({
    'crt',
    'cert',  # Can contain PEM directly in some configs
    'public-key',
})

# Substring-tolerant secret element matching.
#
# REDACT_ELEMENTS above is an exact-match set, which misses the concatenated
# spellings pfSense and its packages actually emit: <rocommunity>/<rwcommunity>
# rather than <community>, <radiussecret> rather than <radius_secret>,
# <auth_pass>, <ipsecpsk>, <tlspskvalue>, <passwordagain> and so on.
#
# Matching is deliberately substring-based (not \b-anchored) because those
# concatenated forms are precisely what leaks. False positives are handled by
# SECRET_TAG_DENYLIST below rather than by narrowing the pattern - consistent
# with this tool's general stance that over-redaction beats under-redaction.
#
# One pattern serves both elements and attributes. They previously disagreed -
# 'bearer', 'cookie' and 'signature' were secrets as attribute names but not as
# element names, and 'credentials', 'privkey', 'psk' and 'community' were the
# reverse - which no threat model justifies. SENSITIVE_ATTR_PATTERN below is an
# alias of this, so the two cannot drift apart again.
#
# Two anchoring styles, deliberately mixed:
#
#   substring     for names that only ever mean one thing, however they are
#                 concatenated ('radiussecret', 'ipsecpsk', 'passwordagain')
#   \b-anchored   for short names that are common substrings of innocent ones.
#                 'auth' is a credential; 'author' is not. 'signature' is;
#                 'signature_algorithm' is not.
SECRET_NAME_PATTERN = re.compile(
    r'passw(?:or)?d|passphrase|(?:^|[_-])pass(?:$|[_-])|pwd'
    r'|psk|pre-?shared-?key|shared-?key'
    r'|secret|token|community|credential|bindpw|licen[cs]e|webhook'
    r'|api[_-]?key|account-?key|authorized-?keys'
    r'|priv(?:ate)?[_-]?key|key(?:s)?$|[_-]key\d*$'
    # Credential-bearing names measured as missed against real package configs
    r'|key(?:data|store|material|blob)'
    r'|otpseed|totp|nonce|salt|seed|digest|hash'
    r'|session[_-]?id|authorization'
    # Word-anchored: secrets in their own right, substrings of innocent names
    r'|\b(?:auth(?:[_-]key|[_-]token|entication)?|bearer|cookie|signature)\b',
    re.IGNORECASE
)

# Retained under its historical name: imported by tests and by anything reading
# the module as documentation. There is one pattern now, not two.
SECRET_TAG_PATTERN = SECRET_NAME_PATTERN

# Certificate-ish tags are redacted only when the content actually looks like
# PEM/blob material, so short certificate *references* (refid-style IDs, which
# are useful for understanding config structure) survive intact.
CERT_TAG_PATTERN = re.compile(r'cert(?:ificate)?s?$|ssloffload', re.IGNORECASE)

# The placeholders this module writes. Recognised on the way back in so that
# redacting an already-redacted file is a no-op: without this, the short value
# '[REDACTED_CERT_OR_KEY]' fails to resolve as a certificate reference on a
# second pass and degrades to the less informative '[REDACTED]'.
REDACTION_PLACEHOLDERS: frozenset[str] = frozenset({
    '[REDACTED]', '[REDACTED_CERT_OR_KEY]',
})

# Tags that match SECRET_TAG_PATTERN but are not secrets.
#
# IMPORTANT: this deny-list gates SECRET_TAG_PATTERN/CERT_TAG_PATTERN only. It
# must never be consulted for REDACT_ELEMENTS or CERT_KEY_ELEMENTS membership -
# 'public-key' is in CERT_KEY_ELEMENTS and must keep its existing PEM/length
# behaviour.
SECRET_TAG_DENYLIST: frozenset[str] = frozenset({
    # Certificate/key references and metadata, not key material
    'certref', 'caref', 'ssl-certref', 'sslcertref', 'keylen', 'keyid',
    'crypto', 'tokenize', 'keyname',
    'publickey', 'pubkey', 'public-key', 'sshdkeyonly',
    # Observed false positives in real pfSense/package configs
    'pass_order',            # Snort/Suricata rule ordering
    'password_type',         # Indicates hashing scheme, not a credential
    'snortcommunityrules',   # Boolean "use community ruleset" toggle
    'sendcommunity',         # Boolean toggle
    'source_hash_key',       # HAProxy load-balancing algorithm selector
    # Algorithm selectors admitted by the widened name pattern. Each names a
    # choice of algorithm; none can hold that algorithm's output.
    'hash-algorithm', 'hash-algorithm-option', 'hashalgo', 'hashalgorithm',
    'hash_algorithm', 'hashtype', 'hash_type', 'hashsize',
    'digestalgo', 'digest_algorithm', 'digest-algorithm', 'digesttype',
    'saltlen', 'saltlength', 'seedlen',
    # OpenVPN directives whose names begin with the word 'auth'
    'auth-retry', 'auth-retry-none', 'auth-nocache',
})

# Element names whose meaning depends on the value rather than the name.
# <digest>SHA384</digest> selects an algorithm; <digest>9f86d081…</digest> is
# one's output. pfSense uses the same spelling for both in IPsec and OpenVPN,
# so the name alone cannot decide and the value is consulted.
ALGORITHM_NAMED_ELEMENTS: frozenset[str] = frozenset({
    'digest', 'hash',
})

# The complete set of values that keep an ALGORITHM_NAMED_ELEMENTS element. A
# closed list rather than a shape test: anything outside it in one of those
# elements is treated as a secret, which is the safe direction.
ALGORITHM_VALUE_NAMES: frozenset[str] = frozenset({
    'md5', 'sha1', 'sha-1', 'sha224', 'sha-224', 'sha256', 'sha-256',
    'sha384', 'sha-384', 'sha512', 'sha-512',
    'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
    'hmac-md5', 'hmac-sha1', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512',
    'aesxcbc', 'aes-xcbc', 'aescmac', 'aes-cmac',
    'bcrypt', 'scrypt', 'argon2', 'argon2i', 'argon2id', 'pbkdf2',
    'none', 'null', 'auto', 'default',
})


def _is_secret_query_param(name_lower: str, value: str) -> bool:
    """Whether a URL query parameter carries a credential

    The deny-list is consulted before the pattern, so a name that merely looks
    secret-ish ('keylen', 'certref') is not redacted on the strength of a
    substring match.
    """
    return (bool(value)
            and name_lower not in SECRET_TAG_DENYLIST
            and bool(SECRET_TAG_PATTERN.search(name_lower)))


# Opaque free-text containers that routinely carry credentials inline.
# custom_options is the standard place for OpenVPN/Unbound/Squid directives and
# frequently holds askpass, auth-user-pass and inline keys.
BLOB_TEXT_ELEMENTS: frozenset[str] = frozenset({
    'custom_options', 'custom_options_squid3', 'advanced', 'advancedoptions',
    'userparams', 'upsd_users', 'objectparameters', 'advanced_bind',
    'detail',
})

# Free-text/identifier elements redacted only under --redact-descriptions.
DESCRIPTION_ELEMENTS: frozenset[str] = frozenset({
    'descr', 'detail', 'hostname', 'ssid',
})

# Attribute names holding free prose rather than structure. Redacted under
# --redact-descriptions, the same flag and for the same reason as the elements
# above: an operator's note is where a PIN, a circuit reference or a personal
# name ends up, and no pattern reliably picks those out of a sentence.
#
# SENSITIVE_ATTR_PATTERN already catches attributes *named* for a secret. This
# covers the ones whose name says nothing, which is why the value has to go
# wholesale rather than be scanned.
DESCRIPTION_ATTRIBUTES: frozenset[str] = frozenset({
    'descr', 'description', 'note', 'notes', 'detail', 'details',
    'comment', 'comments', 'label', 'title',
})

# key<sep>value scanner for BLOB_TEXT_ELEMENTS. Matches anywhere in a line, not
# just at its start, so '[admin] password=secret' (NUT upsd_users format) is
# caught as well as a bare 'password=secret'.
#
# The (?!//) guard stops a URL scheme being read as a key=value pair: without
# it 'https://host/x?token=SECRET' matches as key='https', value='//host/...',
# which consumes the whole URL and hides the token from further scanning.
BLOB_KV_RE = re.compile(
    r'(?P<key>[A-Za-z0-9_.\-]+)(?P<sep>\s*[=:]\s*)(?P<value>(?!//)[^\s,;]+)'
)

# Directive style: 'askpass /path/to/passfile' - name and argument separated by
# whitespace, at the start of a line.
BLOB_DIRECTIVE_RE = re.compile(
    r'^(?P<indent>\s*)(?P<key>[A-Za-z0-9_.\-]+)(?P<sep>\s+)(?P<value>\S.*?)(?P<trail>\s*)$'
)

# Directive names inside blob text whose *argument* is a secret even though the
# directive name itself does not match SECRET_TAG_PATTERN.
BLOB_SECRET_DIRECTIVES: frozenset[str] = frozenset({
    'askpass', 'auth-user-pass', 'tls-auth', 'tls-crypt', 'tls-crypt-v2',
    'secret', 'crl-verify', 'http-proxy-user-pass',
})

# High-entropy blob detection for elements not otherwise recognised.
BLOB_MIN_SCAN_LENGTH: int = 32
BASE64ISH_RE = re.compile(r'^[A-Za-z0-9+/=_\-]+$')
HEXISH_RE = re.compile(r'^[0-9A-Fa-f]+$')

# A UUID is 36 characters of hex and hyphens, which satisfies every shape test
# below. pfSense uses them as interface and object identifiers, and they carry
# no secret, so they are excluded by shape rather than by tuning a threshold
# until they happen to fall outside it.
UUID_RE = re.compile(
    r'\A[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-'
    r'[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\Z'
)

# Opaque-value thresholds.
#
# 32 stays the floor at which a value is considered at all.
#
# From 32 to OPAQUE_UNIFORM_MIN_LENGTH, a Base64-shaped value must still mix
# character classes: this is the band where an ordinary word collides with an
# encoded one, and 'administratorsonlyplease' is not a key.
#
# At OPAQUE_UNIFORM_MIN_LENGTH and above, uniformity stops meaning anything. An
# all-lowercase token, an all-uppercase token and a digest spelled only in a-f
# are all plausible secrets at that length and none of them mixes classes. 36
# rather than the 48 the review suggested, because the shortest single-class
# secrets measured in package configs sit just above 36, and the one structural
# value at that length - the UUID - is excluded above by shape.
#
# Hex-shaped values skip the band entirely: 32 hex characters is a 128-bit key
# or digest whatever subset of the alphabet it uses, and requiring a digit made
# a digest spelled only in a-f invisible.
OPAQUE_UNIFORM_MIN_LENGTH: int = 36

# Shannon entropy floor, in bits per character. Rejects values that satisfy a
# shape but carry nothing: all-zero fields, repeated fill, and padding. A
# base64 secret scores around 5; 'deadbeef' repeated scores 2.3; 40 zeroes
# score 0.
MIN_OPAQUE_ENTROPY_BITS: float = 2.0

# ==========================================================================
# Bounded inspection of encoded values
# ==========================================================================
# A value that decodes to key material is key material; an encoding is not a
# protection. Decoding attacker-influenced text is also where a scanner turns
# into a denial of service, so every dimension is bounded and named here rather
# than being implicit in the loop.
MAX_DECODE_DEPTH: int = 3            # single, double and triple wrapping
MAX_DECODE_SOURCE_CHARS: int = 262144   # encoded text considered per value
MAX_DECODED_BYTES: int = 65536       # produced per decode; a PEM key is ~3 KiB
MAX_DECODE_OPERATIONS: int = 32      # total decodes per value, across all depths
MIN_DECODE_CANDIDATE_CHARS: int = 24  # shorter runs cannot hide a key header

# A run long enough that its decoding could not exceed MAX_DECODED_BYTES.
MAX_ENCODED_RUN_CHARS: int = (MAX_DECODED_BYTES * 4) // 3 + 4

# Base64 and Base64URL share an alphabet apart from two characters, so one
# scanner finds both and the decoder tries each mapping.
ENCODED_RUN_RE = re.compile(
    r'[A-Za-z0-9+/=_-]{%d,}' % MIN_DECODE_CANDIDATE_CHARS
)
_URLSAFE_TO_STANDARD = str.maketrans('-_', '+/')

# PEM headers that denote private key material.
#
# Unlike a certificate, there is no configuration in which sharing one of these
# is intended, so a match is removed in every mode and in every element or
# attribute. That makes this the one classification in the module with no
# over-redaction trade-off to weigh.
#
# The algorithm qualifier is a bounded repetition rather than '.*' so the
# pattern cannot backtrack pathologically over attacker-supplied text. It
# covers PRIVATE KEY, RSA/EC/DSA/ED25519 PRIVATE KEY, ENCRYPTED PRIVATE KEY,
# OPENSSH PRIVATE KEY, SSH2 ENCRYPTED PRIVATE KEY and PGP PRIVATE KEY BLOCK,
# plus OpenVPN's static key, which pfSense writes for tls-auth and tls-crypt.
PRIVATE_KEY_PEM_RE = re.compile(
    r'-----BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----'
    r'|-----BEGIN OPENVPN STATIC KEY(?: V\d)?-----'
)

# Compact JWT. Anchored on 'eyJ', the Base64 of '{"' with which every compact
# JOSE header begins, so an ordinary dotted string - a hostname, a version, an
# IPv4 address, a filename - cannot reach it. Segment lengths are bounded to
# keep matching linear.
JWT_PREFIXED_RE = re.compile(
    r'eyJ[A-Za-z0-9_-]{5,8192}\.[A-Za-z0-9_-]{4,8192}\.[A-Za-z0-9_-]{0,8192}'
)

# The general three-segment compact-token shape. Matching this alone would flag
# any sufficiently long dotted string, so a match only counts when the first
# segment actually decodes to a JOSE header (see _segment_is_jose_header). That
# catches header encodings the 'eyJ' prefix misses without inventing findings.
COMPACT_TOKEN_RE = re.compile(
    r'(?<![A-Za-z0-9_.-])'
    r'([A-Za-z0-9_-]{12,8192})\.([A-Za-z0-9_-]{8,8192})\.([A-Za-z0-9_-]{0,8192})'
)
MAX_TOKEN_CANDIDATES: int = 32


def _b64_decode_bounded(candidate: str) -> bytes | None:
    """Strictly decode one Base64 run, or None if it is not decodable

    Strict validation matters: without it, base64 silently discards characters
    outside the alphabet and manufactures a decoding for text that was never
    encoded. Padding is added rather than required, because values stored in
    attributes and JSON commonly arrive with it stripped.
    """
    body = ''.join(candidate.split()).rstrip('=')
    if not body:
        return None

    padded = body + '=' * (-len(body) % 4)
    for alphabet in (padded, padded.translate(_URLSAFE_TO_STANDARD)):
        decoded = _b64_decode_strict(alphabet)
        if decoded is not None:
            return decoded
    return None


def _b64_decode_strict(padded: str) -> bytes | None:
    """One strict decode attempt, refusing anything over MAX_DECODED_BYTES"""
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None

    if len(decoded) > MAX_DECODED_BYTES:
        return None
    return decoded or None


def _decode_encoded_runs(layer: str, budget: int) -> tuple[list[str], int]:
    """Decode the encoded runs in one layer, spending a shared operation budget

    The budget is shared across the whole traversal rather than per layer, so
    the total work for a value is bounded no matter how the runs are
    distributed between depths.
    """
    produced: list[str] = []
    # finditer, not findall: the loop usually stops on the operation budget
    # long before the runs are exhausted, so materialising them all first is
    # work thrown away on exactly the large values that make it expensive.
    for match in ENCODED_RUN_RE.finditer(layer):
        run = match.group()
        if budget <= 0:
            break
        if len(run) > MAX_ENCODED_RUN_CHARS:
            continue
        budget -= 1
        decoded = _b64_decode_bounded(run)
        if decoded is not None:
            produced.append(decoded.decode('utf-8', errors='replace'))
    return produced, budget


def _next_decode_layer(
    frontier: list[str], seen: set[str], budget: int
) -> tuple[list[str], int]:
    """Decode every layer in the frontier once, dropping what is not new

    A decoding that reproduces something already seen is a dead end - it means
    the value is not really layered - so it is dropped rather than expanded
    again.
    """
    produced: list[str] = []
    for layer in frontier:
        decoded, budget = _decode_encoded_runs(layer, budget)
        produced.extend(item for item in decoded if item not in seen)
        seen.update(decoded)
    return produced, budget


def decoded_layers(text: str, max_depth: int = MAX_DECODE_DEPTH) -> list[str]:
    """Successive decodings of the encoded runs in `text`, bounded throughout

    Stops on decode failure, on a layer that reproduces something already seen,
    at `max_depth`, at MAX_DECODE_OPERATIONS, and at the size limits. Returns
    the decoded layers only - never the input - so a caller cannot accidentally
    re-scan the original and double-count it.

    Decoded content is inspected in memory and discarded. It is never logged,
    never sampled and never placed in an exception message: it is by definition
    the plaintext of something someone chose to encode.
    """
    if len(text) < MIN_DECODE_CANDIDATE_CHARS:
        return []

    source = text[:MAX_DECODE_SOURCE_CHARS]
    layers: list[str] = []
    frontier = [source]
    seen = {source}
    budget = MAX_DECODE_OPERATIONS

    for _ in range(max_depth):
        frontier, budget = _next_decode_layer(frontier, seen, budget)
        layers.extend(frontier)
        if not frontier or budget <= 0:
            break

    return layers


def contains_private_key_material(text: str) -> bool:
    """Whether `text` holds private-key PEM, directly or through an encoding

    Checked before every heuristic in the module, and acted on in every mode.
    """
    if not text:
        return False
    if PRIVATE_KEY_PEM_RE.search(text):
        return True
    return any(PRIVATE_KEY_PEM_RE.search(layer) for layer in decoded_layers(text))


def _segment_is_jose_header(segment: str) -> bool:
    """Whether a compact-token segment decodes to a JOSE header object

    A JWT header is a JSON object naming an algorithm. Requiring both facts is
    what keeps the general three-segment shape from matching a long hostname.
    """
    decoded = _b64_decode_bounded(segment)
    if decoded is None:
        return False
    return decoded.lstrip()[:1] == b'{' and b'"alg"' in decoded[:512]


def contains_jwt(text: str) -> bool:
    """Whether `text` contains a compact JWT-style token

    Treated as a secret in every mode. The token's own segments are never
    logged or sampled: a JWT header names the issuer and the payload usually
    names the subject, so even a prefix is identifying.
    """
    if not text or '.' not in text:
        return False
    if JWT_PREFIXED_RE.search(text):
        return True

    candidates = islice(
        COMPACT_TOKEN_RE.finditer(text[:MAX_DECODE_SOURCE_CHARS]),
        MAX_TOKEN_CANDIDATES
    )
    return any(_segment_is_jose_header(match.group(1)) for match in candidates)


# What an unambiguous secret is, and which placeholder replaces it. Ordered:
# a value is classified by the first entry that matches.
UNAMBIGUOUS_SECRET_KINDS: tuple[tuple[str, str, str], ...] = (
    ('private-key', 'Cert/Key', '[REDACTED_CERT_OR_KEY]'),
    ('jwt', 'Secret', '[REDACTED]'),
)


def unambiguous_secret_kind(text: str) -> str | None:
    """Classify a value that is a credential whatever contains it

    Returns 'private-key', 'jwt', or None. Both are structural facts about the
    value rather than inferences from its name or its shape, so neither carries
    the over-redaction risk that keeps the opaque-value heuristic in
    report-only mode by default.

    One function rather than a pair of checks at each call site, because there
    are two call sites - element text and attribute values - and they must not
    drift. The same reasoning produced one shared predicate for element and
    attribute *names*; this is that principle applied to values.
    """
    if contains_private_key_material(text):
        return 'private-key'
    if contains_jwt(text):
        return 'jwt'
    return None


def _redaction_for(kind: str) -> tuple[str, str]:
    """The (statistics category, placeholder) pair for a secret kind"""
    for name, category, placeholder in UNAMBIGUOUS_SECRET_KINDS:
        if name == kind:
            return category, placeholder
    raise ValueError(f'unknown secret kind: {kind}')  # pragma: no cover - unreachable


def shannon_entropy_bits(value: str) -> float:
    """Shannon entropy of `value`, in bits per character

    One bounded pass over a string the caller has already length-capped.
    """
    if not value:
        return 0.0

    total = len(value)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in Counter(value).values()
    )


def _is_opaque_secret_shape(compact: str) -> bool:
    """Whether a whitespace-free value is shaped like an opaque secret

    See OPAQUE_UNIFORM_MIN_LENGTH for why the bands are where they are. Every
    band additionally requires entropy above MIN_OPAQUE_ENTROPY_BITS, so a
    value that satisfies a shape while carrying nothing is not reported.
    """
    if UUID_RE.match(compact):
        return False

    hex_shaped = bool(HEXISH_RE.match(compact))
    if not (hex_shaped or BASE64ISH_RE.match(compact)):
        return False

    if shannon_entropy_bits(compact) < MIN_OPAQUE_ENTROPY_BITS:
        return False

    if hex_shaped or len(compact) >= OPAQUE_UNIFORM_MIN_LENGTH:
        return True

    return _has_mixed_character_classes(compact, hex_only=False)

# Final labels that are file extensions rather than TLDs. FQDN_RE is
# deliberately broad, so without this 'list.txt' and 'backup-2026.tar.gz' are
# rewritten to example.com - silently corrupting the pfBlockerNG feed names,
# script paths and cron commands people share a config to get help with.
#
# Only unambiguous entries belong here: '.sh', '.pl', '.io', '.zip' and '.mov'
# are all real TLDs, so 'haproxy.sh' cannot be resolved by extension alone and
# is handled by the path-context rule in _redact_fqdns_safe instead.
FILE_EXTENSIONS: frozenset[str] = frozenset({
    'txt', 'log', 'conf', 'cfg', 'ini', 'yaml', 'yml', 'json', 'xml', 'csv',
    'rules', 'list', 'lst', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'zst', 'bak',
    'pem', 'crt', 'cer', 'csr', 'der', 'p12', 'pfx', 'jks', 'keystore',
    'sql', 'sqlite', 'db', 'dat', 'pid', 'sock', 'lock', 'tmp', 'swp',
    'php', 'cgi', 'inc', 'tpl', 'patch', 'diff', 'sample', 'orig', 'dist',
})

# Placeholder used to hide URLs from later text passes. NUL is not legal in XML
# content, so a placeholder can only ever be one this module wrote.
URL_PLACEHOLDER_RE = re.compile(r'\x00URL(\d+)\x00')

# What a redacted address looks like in the output. Named because they are
# also matched on the way back *in*: a token already carrying one of these has
# been redacted before, and must not be counted or rewritten a second time.
MASKED_IPV4 = 'XXX.XXX.XXX.XXX'
MASKED_IPV6 = 'XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX'
MASKED_IP_TOKENS: frozenset[str] = frozenset({
    MASKED_IPV4, MASKED_IPV6, f'[{MASKED_IPV6}]',
})

# Summary lines, in print order. Labels are parsed by the StatsParser fixture in
# tests/conftest.py, so the text must not change.
STAT_LABELS: tuple[tuple[str, str], ...] = (
    ('secrets_redacted', 'Passwords/keys/secrets'),
    ('certs_redacted', 'Certificates'),
    ('ips_redacted', 'IP addresses'),
    ('macs_redacted', 'MAC addresses'),
    ('domains_redacted', 'Domain names'),
    ('emails_redacted', 'Email addresses'),
    ('urls_redacted', 'URLs'),
    ('url_secrets_redacted', 'Secrets in URL paths/queries'),
)

# Sample categories, in the order they are printed for --dry-run-verbose.
SAMPLE_CATEGORIES: tuple[str, ...] = ('IP', 'URL', 'FQDN', 'MAC', 'Secret', 'Cert/Key')

# Documentation ranges reserved for examples: RFC 5737 (IPv4) and RFC 3849
# (IPv6). In anonymise mode these are the values this tool generates, so seeing
# one means it has already been masked. Built once at import rather than per
# call - the check runs for every IP-like token in the config.
RFC_DOC_NETWORKS_V4: tuple[IPNetwork, ...] = (
    ipaddress.ip_network('192.0.2.0/24'),
    ipaddress.ip_network('198.51.100.0/24'),
    ipaddress.ip_network('203.0.113.0/24'),
)
RFC_DOC_NETWORK_V6: IPNetwork = ipaddress.ip_network('2001:db8::/32')


def _disqualified_as_blob(compact: str) -> bool:
    """Whether a candidate is ruled out as encoded key material on shape alone

    Too short to be a key, or containing whitespace - which encoded blobs do
    not, once line wrapping has been removed, but ordinary prose does.
    """
    return len(compact) < BLOB_MIN_SCAN_LENGTH or ' ' in compact or '\t' in compact


def _has_mixed_character_classes(compact: str, hex_only: bool) -> bool:
    """Check a candidate blob mixes character classes rather than being uniform

    A long run of a single class - a numeric ID, or a lowercase word - is far
    more likely to be ordinary content than encoded key material. Hex strings
    get a looser rule since they cannot contain much variety by definition.
    """
    has_digit = any(c.isdigit() for c in compact)
    has_upper = any(c.isupper() for c in compact)
    has_lower = any(c.islower() for c in compact)

    if hex_only:
        return has_digit and (has_upper or has_lower)
    return has_digit + has_upper + has_lower >= 2


def is_rfc_documentation_ip(ip: IPAddress) -> bool:
    """Check whether an address is in a reserved documentation range

    Shared by the three places that need it: _mask_ip_like_tokens,
    _is_already_masked_host and _normalise_masked_url. Each previously inlined
    its own copy and rebuilt the network objects on every call.
    """
    if ip.version == 4:
        return any(ip in net for net in RFC_DOC_NETWORKS_V4)
    return ip in RFC_DOC_NETWORK_V6

# Endpoints whose credential lives in the URL path rather than a query string.
# For these the path token *is* the authorisation - anyone holding the URL can
# post as that integration - so it is redacted in every mode, not only under
# --aggressive.
#
# Path redaction is otherwise gated behind --aggressive because feed URLs
# (pfBlockerNG and similar) legitimately carry long path segments that
# redaction would destroy. These entries are narrow enough not to catch those:
# each is an exact host plus the path prefix its webhook API actually uses.
#
# Matched on the exact host, never a suffix. 'hooks.slack.com.example.net' is a
# different host and must not inherit the rule.
WEBHOOK_URL_PREFIXES: tuple[tuple[str, str], ...] = (
    ('hooks.slack.com', '/services/'),
    ('discord.com', '/api/webhooks/'),
    ('discordapp.com', '/api/webhooks/'),
    ('ptb.discord.com', '/api/webhooks/'),
    ('canary.discord.com', '/api/webhooks/'),
    # Telegram puts 'bot<id>:<token>' in the first path segment.
    ('api.telegram.org', '/bot'),
    # Microsoft Teams, connector-style (the pre-Workflows endpoint).
    ('outlook.office.com', '/webhook/'),
    ('outlook.office365.com', '/webhook/'),
)

# Providers that put the tenant in a subdomain, so the host cannot be matched
# exactly. Matched as a suffix *including the leading dot*, which is what stops
# 'eviloutlook.office.com' or 'notwebhook.office.com' from qualifying.
#
# Kept apart from WEBHOOK_URL_PREFIXES on purpose. Suffix matching is the looser
# rule and the easier one to get wrong, so it applies only to domains listed
# here rather than to the whole set.
WEBHOOK_URL_SUFFIXES: tuple[tuple[str, str], ...] = (
    ('.webhook.office.com', '/webhookb2/'),
)

# Deliberately absent: Mattermost, Rocket.Chat and other self-hosted tools put
# their webhooks at '/hooks/<token>' on whatever host the operator chose. There
# is no host to match, and treating any '/hooks/' path as a credential would
# redact ordinary paths on unrelated servers. Those need --aggressive.


def _is_webhook_url(host: str, path: str) -> bool:
    """Whether a URL is a known webhook endpoint carrying its token in the path

    The path is compared case-insensitively even though RFC 3986 makes paths
    case-sensitive. Every prefix here is lowercase, so folding case can only
    add matches, never remove one, and the additions are all still webhook
    URLs: '/Services/' on hooks.slack.com is not something else. Comparing
    exactly meant a config written with '/Services/' kept its token, which is
    the failure this whole rule exists to prevent.
    """
    host_lower = host.lower()
    path_lower = path.lower()

    if any(host_lower == known and path_lower.startswith(prefix)
           for known, prefix in WEBHOOK_URL_PREFIXES):
        return True

    return any(host_lower.endswith(suffix) and path_lower.startswith(prefix)
               for suffix, prefix in WEBHOOK_URL_SUFFIXES)


# URL path segment credential detection.
# 20 because AWS access key IDs (AKIA...) are exactly 20 characters.
SECRETISH_SEGMENT_MIN_LENGTH: int = 20
# Above this length an all-letter segment is treated as a token even without a
# digit. Set clear of 'Open_VM_Tools_package' (21), the route name the digit
# requirement exists to protect.
DIGITLESS_TOKEN_LENGTH: int = 24

IP_CONTAINING_ELEMENTS: frozenset[str] = frozenset({
    'ipaddr', 'ipaddrv6', 'gateway', 'dnsserver', 'hostname', 'domain',
    'remote-gateway', 'tunnel_network', 'local_network', 'remote_network',
    'server', 'host', 'address', 'subnet', 'subnetv6',
    'vip', 'virtualip', 'monitor', 'monitorip', 'monitorip6',
    'endpoint', 'src', 'dst', 'peer', 'dns',
    'allowedips', 'allowed_ips', 'allowed-ips',  # WireGuard variants
    'remoteserver', 'remoteserver2', 'remoteserver3',
    'sourceip', 'syscontact', 'fromaddress',
    'username',  # Can contain emails in SMTP/notification contexts
    'linklocal', 'repo', 'mirror', 'backup',
    'url',  # pfSense configs often embed literal URLs in <url> elements
    'mac',  # MAC addresses in <mac> tags
})

# Attribute names are classified by the same pattern as element names.
#
# These were two separate patterns, and they disagreed: 'bearer', 'cookie' and
# 'signature' were secrets only as attributes, 'credentials', 'privkey', 'psk',
# 'passphrase', 'licensekey' and 'community' only as elements. A name means the
# same thing wherever it appears, so there is one pattern and this is an alias
# of it. Kept as a name because tests and readers refer to it.
SENSITIVE_ATTR_PATTERN = SECRET_NAME_PATTERN


# ==========================================================================
# 3. VERSION
# ==========================================================================
def resolve_version() -> str:
    """Resolve the package version, whatever the execution context

    Used by both --version and the redaction comment stamped into output.

    Order:
    1. The package's __version__ (normal installed/module use)
    2. pyproject.toml, for running redactor.py directly from a source checkout,
       where the relative import is unavailable
    3. "unknown"

    No version literal is hardcoded here on purpose: an earlier hardcoded
    fallback drifted two releases behind, and reporting a wrong version is
    worse than reporting none.
    """
    try:
        from . import __version__  # pylint: disable=import-outside-toplevel,cyclic-import
        return __version__
    except (ImportError, AttributeError):
        pass

    try:
        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            content = pyproject_path.read_text(encoding='utf-8')
            match = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
            if match:
                return match.group(1)
    except (OSError, UnicodeDecodeError):
        pass

    return "unknown"


@functools.lru_cache(maxsize=256)
def _idna_encode(domain: str) -> str:
    """Cache IDNA encoding for performance (domains are often repeated)

    Args:
        domain: Domain name to encode

    Returns:
        IDNA-encoded (punycode) ASCII string, or original if encoding fails
    """
    try:
        return domain.encode('idna').decode('ascii')
    except UnicodeError:
        # IDNA encoding failed (malformed domain or unsupported characters)
        # UnicodeError catches both UnicodeDecodeError and UnicodeEncodeError
        return domain


# Prologs are a few bytes in any real config, but a hostile file can pad one
# with a large comment, so the scan below grows on demand rather than peeking
# at a fixed-size prefix.
_PROLOG_CHUNK: int = 65536
_UTF8_BOM: bytes = b'\xef\xbb\xbf'
_DOCTYPE_DECL: bytes = b'<!DOCTYPE'

# Ceiling on how much prolog will be examined. The largest prolog in this
# project's own fixtures is 68 bytes, so this is roughly 15,000x any real one.
# It exists to bound the work a hostile file can demand: the buffer is
# rescanned on each refill, which is quadratic, and at 50 MB of comment that
# is seconds rather than milliseconds.
#
# Exceeding it *refuses* the file. A cap that instead stopped scanning and
# carried on parsing would reintroduce the bypass this scan exists to close -
# a DOCTYPE hidden behind one byte more than the cap - which is the whole
# reason a fixed-size prefix check was rejected in the first place.
_PROLOG_MAX: int = 1024 * 1024

# Constructs that may legally precede the root element, as (opener, closer).
_PROLOG_SKIPPABLE: tuple[tuple[bytes, bytes], ...] = (
    (b'<!--', b'-->'),  # comment
    (b'<?', b'?>'),     # XML declaration or processing instruction
)


def _skip_one_prolog_construct(data: bytes, pos: int) -> int | None:
    """Advance past a single comment or processing instruction at pos

    Returns the offset just after it, `pos` unchanged when no construct starts
    here, or None if the construct is unterminated within `data`.
    """
    for opener, closer in _PROLOG_SKIPPABLE:
        if not data.startswith(opener, pos):
            continue
        end = data.find(closer, pos + len(opener))
        return None if end == -1 else end + len(closer)

    return pos


def _skip_prolog_noise(data: bytes, pos: int) -> int | None:
    """Advance past whitespace, comments and processing instructions

    Returns the offset of the first byte that is none of those, or None if
    `data` ends inside a comment or PI, meaning more input is needed to tell.
    """
    while pos < len(data):
        if data[pos:pos + 1].isspace():
            pos += 1
            continue

        after = _skip_one_prolog_construct(data, pos)
        if after is None or after == pos:
            # None: unterminated, so undecidable. Unchanged: nothing skippable
            # starts here, so this is where the prolog ends.
            return after
        pos = after

    return pos


def _prolog_scan_is_conclusive(data: bytes, pos: int, at_eof: bool) -> bool:
    """Whether enough input is present for the comparison at pos to be final

    The subtle case this guards: a declaration straddling a read boundary. With
    only part of it buffered the comparison would say "no DOCTYPE" and be
    believed, so the scan must wait for either the full length or the end of
    the file.
    """
    return at_eof or len(data) - pos >= len(_DOCTYPE_DECL)


# Distinguishes "this buffer cannot decide yet" from "accept" (None), which a
# bare None would conflate.
_NEED_MORE_INPUT = object()


def _examine_prolog(data: bytes, at_eof: bool) -> str | None | object:
    """Judge the prolog from the bytes read so far

    Returns a refusal reason, None to accept, or _NEED_MORE_INPUT when the
    answer still depends on bytes that have not been read.
    """
    if len(data) > _PROLOG_MAX:
        return (f"its XML prolog exceeds {_PROLOG_MAX // 1024} KiB "
                "without reaching a root element")

    start = len(_UTF8_BOM) if data.startswith(_UTF8_BOM) else 0
    pos = _skip_prolog_noise(data, start)

    if pos is not None and _prolog_scan_is_conclusive(data, pos, at_eof):
        # Compared case-insensitively even though XML requires the upper-case
        # spelling, so that '<!doctype' is refused here rather than relying on
        # the parser to reject it.
        if data[pos:pos + len(_DOCTYPE_DECL)].upper() == _DOCTYPE_DECL:
            return "it declares a DOCTYPE, which pfSense never emits"
        return None

    if at_eof:
        # Unterminated comment or PI. The file is malformed, and ET.parse
        # reports that more precisely than this guard could.
        return None

    return _NEED_MORE_INPUT


def _prolog_refusal_reason(input_file: str) -> str | None:
    """Say why the input's XML prolog is unacceptable, or None if it is fine

    Two refusals, both fail-closed:

    - A DOCTYPE declaration. pfSense never emits one, so its presence means the
      file did not come from pfSense untouched. ElementTree does not resolve
      external entities - a SYSTEM entity raises ParseError, so there is no XXE
      here - but it does expand internal ones, and a few hundred bytes of
      nested definitions expand to gigabytes.
    - A prolog past _PROLOG_MAX, which bounds the work a hostile file can ask
      for without letting an oversized one through unexamined.

    Scanning the whole prolog rather than a fixed-size prefix is the point. A
    DOCTYPE preceded by a comment longer than the window sails straight past a
    prefix check, which would leave the guard passing while doing nothing.
    """
    with open(input_file, 'rb') as handle:
        data = b''
        while True:
            chunk = handle.read(_PROLOG_CHUNK)
            data += chunk
            verdict = _examine_prolog(data, at_eof=not chunk)
            if verdict is not _NEED_MORE_INPUT:
                return verdict


# ==========================================================================
# 4. VERIFICATION
# ==========================================================================
def _import_verifier_module(spelling: str):
    """Try one import spelling for the verifier, returning None if it is absent"""
    try:
        if spelling == 'package':
            from . import verifier  # pylint: disable=import-outside-toplevel,cyclic-import
            return verifier
        import verifier  # pylint: disable=import-outside-toplevel
        return verifier
    except ImportError:
        return None


def _load_verifier():
    """Import the independent verifier, tolerating the single-file deployment

    redactor.py must stay runnable as a lone file - see the module docstring -
    so this cannot be a hard import. Two spellings are tried: the
    package-relative one for a normal installation, and the plain one for a
    redactor.py sitting beside a verifier.py.

    The result is checked for the entry point rather than merely for being
    importable, so an unrelated module called 'verifier' earlier on sys.path
    cannot be mistaken for this one.

    Returning None does NOT mean verification passed. It means verification is
    unavailable, and every caller must treat it that way - see
    PfSenseRedactor.verify_candidate_output.
    """
    for spelling in ('package', 'plain'):
        module = _import_verifier_module(spelling)
        if module is not None and hasattr(module, 'verify_candidate'):
            return module
    return None


VERIFIER = _load_verifier()


def verification_is_available() -> bool:
    """Whether the independent verifier could be imported

    False only in the single-file deployment, where redactor.py was copied out
    without verifier.py beside it.
    """
    return VERIFIER is not None


# ==========================================================================
# 5. REDACTOR
# ==========================================================================
class PfSenseRedactor:  # pylint: disable=too-many-instance-attributes
    """pfSense configuration redactor for sensitive data handling

    Note: This class intentionally has many instance attributes to maintain
    clear separation of concerns and avoid premature optimization. The attributes
    are logically grouped and well-documented.

    Method Naming Convention:
    -------------------------
    - _redact_*(): Modifies data in-place or returns redacted copy
    - _mask_*(): Returns masked/transformed copy for display purposes
    - _is_*(): Boolean predicate check (returns True/False)
    - _validate_*(): Validates input and returns bool
    - _parse_*(): Parses input and returns parsed object
    - _build_*(): Constructs and returns a new object
    - _normalise_*(): Normalises input and returns normalised form
    - _anonymise_*(): Generates consistent aliases for anonymisation
    - _add_*(): Adds item to collection (side effect)
    - _get_*(): Retrieves value without side effects
    - _*_safe(): Includes exception handling/validation (suffix)

    Avoid vague verbs like "handle" - be specific about what the method does.

    Method Groups:
    --------------
    Roughly the order they appear in, and the order redact_element() calls them.

    - Allow-lists            _normalise_domain, _is_domain_allowed, _is_ip_allowed
    - Sample masking         _mask_*_sample, _safe_mask_for_sample, _add_sample
                             (for --dry-run-verbose; never shows a raw secret)
    - IP anonymisation       _parse_ip_token, _anonymise_ip, _counter_to_rfc_ip,
                             _mask_ip_like_tokens
    - Domain anonymisation   _anonymise_domain, _redact_fqdns_safe
    - URL masking            _mask_url and friends; _redact_query_secrets and
                             _redact_path_secrets handle embedded credentials,
                             _redact_netloc_userinfo handles user:pass@host
    - Tag classification     _is_secret_tag, _is_cert_tag, _get_tag_base
    - Element redaction      _should_redact_completely, _redact_cert_key_element,
                             _redact_blob_text*, _redact_unknown_blob_element
    - Entry points           redact_element (recursive walk), redact_config
                             (file in/out), _print_stats

    Ordering inside redact_element() is load-bearing: <key> is checked before
    the generic secret match so the cert/key distinction survives, and
    text_already_processed gates the later passes.
    """

    # Class constants for magic numbers
    SAMPLE_LIMIT: int = 5  # Maximum number of samples to collect per category
    CERT_MIN_LENGTH: int = 50  # Minimum length to treat text as certificate/key blob
    KEY_BLOB_MIN_LENGTH: int = 64  # Minimum length to treat <key> content as PEM blob
    KEY_SHORT_THRESHOLD: int = 40  # Threshold for short key detection (alphanumeric check)
    RETAINED_PATHS_SHOWN: int = 10  # Max retained high-entropy paths listed in the summary

    # Each argument is an independent, user-facing redaction policy toggle
    # mapped 1:1 from a CLI flag; grouping them into a config object would add
    # indirection without removing any of the choices.
    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        keep_private_ips: bool = False,
        anonymise: bool = False,
        aggressive: bool = False,
        fail_on_warn: bool = False,
        allowlist_ips: set[str] | None = None,
        allowlist_domains: set[str] | None = None,
        allowlist_networks: list[IPNetwork] | None = None,
        dry_run_verbose: bool = False,
        redact_url_usernames: bool = False,
        redact_descriptions: bool = False
    ) -> None:
        self.keep_private_ips = keep_private_ips
        self.anonymise = anonymise
        self.aggressive = aggressive
        self.fail_on_warn = fail_on_warn
        self.dry_run_verbose = dry_run_verbose
        self.redact_url_usernames = redact_url_usernames
        self.redact_descriptions = redact_descriptions

        # Element paths of high-entropy values retained (not redacted) so they
        # can be surfaced in the summary for manual review
        self.high_entropy_paths: list[str] = []
        self._path_stack: list[str] = []

        # Whether IPs and domains are redacted on this run. Policy for the whole
        # traversal rather than per element, so they are set once by
        # redact_config rather than threaded through every method beneath it.
        # Defaulted here so redact_element stays callable on a bare element,
        # which is how most of the unit tests drive it.
        self.redact_ips: bool = True
        self.redact_domains: bool = True

        # Independent verification. _input_values is the pre-redaction snapshot
        # the retention comparison needs; last_verification is the result of the
        # most recent redact_config, or None when the verifier was unavailable
        # or has not run. None is never a pass - see verify_candidate_output.
        self._input_values: list = []
        self.last_verification = None

        # Every <refid> defined in the config being processed, so a short value
        # in a certificate-named element can be resolved rather than guessed at.
        # Populated by _collect_refids before the traversal starts; empty here
        # so redact_element stays callable on a bare element, which is how most
        # of the unit tests drive it. An empty set resolves nothing, so those
        # values are treated as secrets - the safe direction.
        self.known_refids: frozenset[str] = frozenset()

        # Get logger instance
        self.logger = logging.getLogger('pfsense_redactor')

        # ReDoS protection constants (instance attributes for easy access)
        self.MAX_URL_LENGTH: int = 2048  # RFC 2616 suggests 2048 as reasonable max
        self.MAX_EMAIL_LENGTH: int = 320  # RFC 5321: 64 (local) + @ + 255 (domain)
        self.MAX_FQDN_LENGTH: int = 253  # RFC 1035: max DNS name length
        self.MAX_TEXT_CHUNK: int = 1048576  # 1MB max for any text element

        # Allow-lists (opt-in, empty by default)
        self._ingest_allowlist_ips(allowlist_ips, allowlist_networks)
        self._ingest_allowlist_domains(allowlist_domains)

        # Sample collection for --dry-run-verbose
        self.sample_limit: int = self.SAMPLE_LIMIT
        self.samples: defaultdict[str, list[tuple[str, str]]] = defaultdict(list)
        self.sample_seen: defaultdict[str, set[str]] = defaultdict(set)

        # Anonymisation maps
        self.ip_aliases: dict[str, str] = {}
        self.domain_aliases: dict[str, str] = {}
        self.ip_counter: int = 0
        self.domain_counter: int = 0

        # Statistics
        self.stats: defaultdict[str, int] = defaultdict(int)

        # Reference module-level constants
        self.always_preserve_ips = ALWAYS_PRESERVE_IPS
        self.redact_elements = REDACT_ELEMENTS
        self.cert_key_elements = CERT_KEY_ELEMENTS
        self.ip_containing_elements = IP_CONTAINING_ELEMENTS

        # Compile all regex patterns for consistency and performance
        # MAC address patterns
        self.MAC_RE = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b')
        self.MAC_CISCO_RE = re.compile(r'\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b')

        # Domain/email/URL patterns
        # ReDoS mitigation: limit repetitions to prevent catastrophic backtracking
        # RFC 5322 local-part chars: alphanumeric + ._%+- and !#$&'*/=?^`{|}~
        # Note: Backslash and quotes require special handling (not included for simplicity)
        self.EMAIL_RE = re.compile(r"(?<!:)\b[A-Za-z0-9._%+\-!#$&'*/=?^`{|}~]+@(?:[A-Za-z0-9-]+\.){1,10}[A-Za-z]{2,}\b")
        # URL pattern: matches common protocols (http, https, ftp, ftps, sftp, ssh, telnet, etc.)
        # This ensures credentials in URLs like ftp://user:pass@host are properly redacted
        self.URL_RE = re.compile(r'\b(?:https?|ftps?|sftp|ssh|telnet|file|smb|nfs)://[^\s<>"\']+\b')
        # FQDN pattern is intentionally broad for security (better to over-redact than under-redact)
        # Matches: label.label.tld where labels are alphanumeric with hyphens
        # TLD can be: 2+ letters OR IDNA A-label (xn-- followed by 2+ alphanumeric/hyphens)
        # This handles both regular TLDs and punycode domains (e.g., foo.xn--p1ai for foo.рф)
        # Note: This may match some non-domains (e.g., version numbers like 1.2.3a) but that's acceptable
        # for a redaction tool where false positives are preferable to false negatives
        self.FQDN_RE = re.compile(r'\b(?:[A-Za-z0-9-]+\.){1,10}(?:[A-Za-z]{2,}|xn--[A-Za-z0-9-]{2,})\b')

        # IP pattern for token matching and splitting
        #
        # '%' is a token character, not a separator. IP_PATTERN already expects
        # a zone identifier to arrive attached to its address, and splitting on
        # '%' severed it: 'fe80::1%igb0' happened to survive because the two
        # halves were masked and copied through separately, but
        # '[fe80::1%igb0]:51820' split into '[fe80::1' and 'igb0]:51820', so the
        # address carried an unbalanced bracket, failed to parse, and was
        # returned untouched. Any bracketed address with a zone leaked, routable
        # ones included.
        self.IP_PATTERN = re.compile(r'^[\[\]]?[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.:+-]+)?[\[\]]?(?::\d+)?$')
        self._ip_token_splitter = re.compile(r'([^0-9A-Za-z\.\:\[\]_+%-])')

        # PEM marker detection
        self.PEM_MARKER = re.compile(
            r'-----BEGIN (?:CERTIFICATE|RSA PRIVATE KEY|EC PRIVATE KEY|ENCRYPTED PRIVATE KEY|PRIVATE KEY|PUBLIC KEY|OPENVPN STATIC KEY|OPENSSH PRIVATE KEY)-----'
        )

    def _ingest_allowlist_ips(self, allowlist_ips: set[str] | None,
                              allowlist_networks: list[IPNetwork] | None) -> None:
        """Populate the IP allow-lists, accepting both addresses and CIDRs"""
        self.allowlist_ip_addrs: set[IPAddress] = set()
        self.allowlist_ip_networks: list[IPNetwork] = list(allowlist_networks or [])

        for ip_str in allowlist_ips or ():
            try:
                self.allowlist_ip_addrs.add(ipaddress.ip_address(ip_str))
            except ValueError:
                pass  # Will be handled as network or error elsewhere

    def _ingest_allowlist_domains(self, allowlist_domains: set[str] | None) -> None:
        """Populate the domain allow-lists in both Unicode and IDNA forms

        Both are stored so a host written either way matches the same entry.
        """
        self.allowlist_domains: set[str] = set()
        self.allowlist_domains_idna: set[str] = set()

        for domain in allowlist_domains or ():
            norm_domain, idna_domain = self._normalise_domain(domain)
            # Skip invalid/empty domains (returns None, None)
            if norm_domain is None:
                continue
            self.allowlist_domains.add(norm_domain)
            if idna_domain and idna_domain != norm_domain:
                self.allowlist_domains_idna.add(idna_domain)

    def _normalise_domain(self, domain: str) -> tuple[str | None, str | None]:
        """Normalise domain: lowercase, strip leading and trailing dots, handle wildcards, compute IDNA

        Returns:
            tuple: (normalised_unicode, normalised_idna) or (None, None) if invalid
        """
        # Strip whitespace first, then leading and trailing dots
        domain = domain.strip().lstrip('.').rstrip('.')

        # Handle wildcard prefix (*.example.org -> example.org for suffix matching)
        if domain.startswith('*.'):
            domain = domain[2:]

        # Lowercase
        domain_lower = domain.lower()

        # CRITICAL: Reject empty domains to prevent bypass vulnerability
        # Malformed entries like ".", "*.", or "*.*" would normalise to empty string
        # which could match ANY domain in suffix matching
        # Also reject domains with any whitespace (space, tab, newline, etc.)
        if not domain_lower or re.search(r'\s', domain_lower):
            return None, None

        # Compute IDNA (punycode) form using cached function
        domain_idna = _idna_encode(domain_lower)

        return domain_lower, domain_idna

    def _is_domain_allowed(self, host: str) -> bool:
        """Check if a domain/hostname is in the allow-list (with suffix and IDNA matching)"""
        if not host:
            return False

        host_l = host.lower().rstrip('.')

        # Compute IDNA form using cached function
        host_idna = _idna_encode(host_l)

        # Both forms are checked so a host written either way matches the
        # same allow-list entry.
        return (self._matches_allowed_domain(host_l, self.allowlist_domains)
                or self._matches_allowed_domain(host_idna, self.allowlist_domains_idna))

    @staticmethod
    def _matches_allowed_domain(host: str, allowed: set[str]) -> bool:
        """Whether host equals, or is a subdomain of, any allowed domain

        The leading dot on the suffix test matters: without it 'notexample.com'
        would match an allow-list entry of 'example.com'.
        """
        return any(host == domain or host.endswith('.' + domain) for domain in allowed)

    def _is_ip_allowed(self, ip: IPAddress) -> bool:
        """Check if an IP address is in the allow-list (including CIDR networks)"""
        if ip in self.allowlist_ip_addrs:
            return True
        return any(ip in net for net in self.allowlist_ip_networks)

    @staticmethod
    def _mask_v4_sample(value: str) -> str:
        """Keep the first two octets and the last, hide the third"""
        parts = value.split('.')
        if len(parts) != 4:
            return value
        return f"{parts[0]}.{parts[1]}.***.{parts[3]}"

    @staticmethod
    def _mask_v6_sample(value: str) -> str:
        """Keep the leading hextets and the last, hide the middle"""
        parts = value.split(':')
        if len(parts) < 3:
            return value
        return f"{parts[0]}:{parts[1]}:*:****::{parts[-1]}"

    def _mask_ip_sample(self, value: str) -> str:
        """Mask IP address for sample display"""
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return value

        if ip.version == 4:
            return self._mask_v4_sample(value)
        return self._mask_v6_sample(value)

    @staticmethod
    def _mask_sample_host(host: str) -> str:
        """Mask a URL host for sample display

        IPv6 results are bracketed because they are substituted back into a
        netloc, which is why this cannot simply reuse _mask_ip_sample.
        """
        try:
            ip = ipaddress.ip_address(host)
        except (ValueError, ipaddress.AddressValueError):
            # Domain: keep the first label and the registrable tail
            host_parts = host.split('.')
            if len(host_parts) >= 3:
                return f"{host_parts[0]}.***.{'.'.join(host_parts[-2:])}"
            if len(host_parts) == 2:
                return f"***.{host}"
            return host

        if ip.version == 4:
            host_parts = host.split('.')
            return f"{host_parts[0]}.{host_parts[1]}.***.{host_parts[3]}" if len(host_parts) == 4 else host

        host_parts = host.split(':')
        return f"[{host_parts[0]}:{host_parts[1]}:*:****::{host_parts[-1]}]" if len(host_parts) >= 3 else f"[{host}]"

    @staticmethod
    def _build_sample_netloc(parts: SplitResult, masked_host: str) -> str:
        """Assemble the netloc for a sample display

        The password becomes *** rather than disappearing, so the preview still
        shows that one was there.
        """
        userinfo = ''
        if parts.username:
            userinfo = f"{parts.username}:***@" if parts.password else f"{parts.username}@"
        netloc = f"{userinfo}{masked_host}"
        if parts.port:
            netloc += f":{parts.port}"
        return netloc

    @staticmethod
    def _join_bracketed_url(parts: SplitResult, netloc: str,
                            path: str, query: str) -> str:
        """Reassemble a sample URL whose masked host is a bracketed IPv6 literal

        Kept as hand assembly rather than urlunsplit, which is how this branch
        has always built the bracketed form.
        """
        result = f"{parts.scheme}://{netloc}{path}"
        if query:
            result += f"?{query}"
        if parts.fragment:
            result += f"#{parts.fragment}"
        return result

    def _mask_url_sample(self, value: str) -> str:
        """Mask URL for sample display

        This is the --dry-run-verbose preview, which users run precisely to
        check what will happen before sharing a config. It masks the host and
        the userinfo password, but must also redact credentials embedded in the
        path and query - printing a live token to the console (and from there
        into CI logs or a pasted ticket) defeats the point of the preview.
        """
        try:
            parts = urlsplit(value)
            host = parts.hostname or ''
            if not host:
                return value

            masked_host = self._mask_sample_host(host)
            netloc = self._build_sample_netloc(parts, masked_host)

            # Credentials also live in the path and query, not just userinfo
            safe_path, _ = self._build_redacted_path(parts.path)
            safe_query, _ = self._build_redacted_query(parts.query)

            if '[' in masked_host:
                return self._join_bracketed_url(parts, netloc, safe_path, safe_query)
            return urlunsplit((parts.scheme, netloc, safe_path, safe_query, parts.fragment))
        except (ValueError, AttributeError):
            pass
        return value

    def _mask_fqdn_sample(self, value: str) -> str:
        """Mask FQDN for sample display"""
        parts = value.split('.')
        if len(parts) >= 3:
            return f"{parts[0]}.***.{'.'.join(parts[-2:])}"
        if len(parts) == 2:
            return f"***.{value}"
        return value

    @staticmethod
    def _mask_colon_mac(value: str) -> str:
        """Six-group form: keep the OUI and the last two groups"""
        parts = value.split(':')
        if len(parts) != 6:
            return value
        return f"{parts[0]}:{parts[1]}:**:**:{parts[4]}:{parts[5]}"

    @staticmethod
    def _mask_dotted_mac(value: str) -> str:
        """Cisco three-group form"""
        parts = value.split('.')
        if len(parts) != 3:
            return value
        return f"{parts[0]}.****.{parts[2]}"

    def _mask_mac_sample(self, value: str) -> str:
        """Mask MAC address for sample display"""
        if ':' in value:
            return self._mask_colon_mac(value)
        if '.' in value:
            return self._mask_dotted_mac(value)
        return value

    def _mask_secret_sample(self, value: str) -> str:
        """Mask secret for sample display"""
        length = len(value)
        return f"{'*' * min(length, 8)} (len={length})"

    def _mask_cert_sample(self, value: str) -> str:
        """Mask certificate/key for sample display"""
        return f"PEM blob (len≈{len(value)})"

    def _safe_mask_for_sample(self, value: str, category: str) -> str:
        """Create a safely masked version of a value for sample display

        Args:
            value: The original value to mask
            category: One of 'IP', 'URL', 'FQDN', 'MAC', 'Secret', 'Cert/Key'

        Returns:
            str: Safely masked version suitable for display
        """
        if not value:
            return value

        maskers: dict[str, Callable[[str], str]] = {
            'IP': self._mask_ip_sample,
            'URL': self._mask_url_sample,
            'FQDN': self._mask_fqdn_sample,
            'MAC': self._mask_mac_sample,
            'Secret': self._mask_secret_sample,
            'Cert/Key': self._mask_cert_sample,
        }

        masker = maskers.get(category)
        return masker(value) if masker else value

    def _add_sample(self, category: str, before: str, after: str) -> None:
        """Add a sample to the collection (if under limit and not duplicate)"""
        if not self.dry_run_verbose:
            return

        # Check if we've already seen this 'before' value in this category
        if before in self.sample_seen[category]:
            return

        if len(self.samples[category]) < self.sample_limit:
            # Record that we've seen this value
            self.sample_seen[category].add(before)
            # Create safely masked version of 'before'
            before_masked = self._safe_mask_for_sample(before, category)
            self.samples[category].append((before_masked, after))

    def _parse_ip_token(self, token: str) -> tuple[IPAddress | None, bool, str]:
        """Parse IP token, handling brackets and zone identifiers"""
        # Strip brackets and split off zone id if present
        bracketed = token.startswith('[') and token.endswith(']')
        core = token[1:-1] if bracketed else token
        core_no_zone, _, zone = core.partition('%')

        try:
            ip = ipaddress.ip_address(core_no_zone)
            return ip, bracketed, zone
        except ValueError:
            return None, bracketed, zone

    def _anonymise_ip(self, ip_str: str) -> str:
        """Generate a consistent alias for an IP address

        Also adds the corresponding RFC documentation IP to the allowlist
        to prevent re-redaction on subsequent runs.
        """
        if ip_str not in self.ip_aliases:
            self.ip_counter += 1
            alias = f"IP_{self.ip_counter}"
            self.ip_aliases[ip_str] = alias

            # Add corresponding RFC IP to allowlist (defence in depth)
            # This prevents re-redaction if the alias is later converted to RFC IP
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                counter = self.ip_counter
                rfc_ip = self._counter_to_rfc_ip(counter, ip_obj.version == 6)
                self.allowlist_ip_addrs.add(ipaddress.ip_address(rfc_ip))
            except ValueError:
                pass  # Should never happen with valid IPs, but be defensive

        return self.ip_aliases[ip_str]

    def _counter_to_rfc_ip(self, counter: int, is_ipv6: bool) -> str:
        """Convert counter to RFC documentation IP address

        Maps counter values to sequential IPs within RFC documentation ranges:
        - IPv4: RFC 5737 ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
          Total: 762 usable addresses (254 per range, excluding .0 and .255)
        - IPv6: RFC 3849 range (2001:db8::/32)
          Total: 65535 usable addresses

        When counters exceed RFC ranges, falls back to RFC 1918 private ranges
        to avoid duplicate mappings whilst maintaining valid IP addresses.

        Args:
            counter: The IP counter value (1-based)
            is_ipv6: True for IPv6, False for IPv4

        Returns:
            str: RFC documentation IP address or fallback private IP
        """
        if is_ipv6:
            return self._counter_to_rfc_ipv6(counter)
        return self._counter_to_rfc_ipv4(counter)

    def _counter_to_rfc_ipv6(self, counter: int) -> str:
        """Map a counter into RFC 3849 (2001:db8::/32), then RFC 4193 on overflow"""
        # Map counter to last hextet (1..65535)
        if counter <= 0xFFFF:
            return f"2001:db8::{counter:x}"

        # IPv6 overflow: use RFC 4193 Unique Local Addresses (ULA)
        # fd00::/8 range for overflow addresses
        # Log warning on first overflow
        if counter == 0xFFFF + 1:
            self.logger.warning(
                "[!] Warning: Exceeded RFC 3849 IPv6 limit (65535 addresses). "
                "Using RFC 4193 ULA range (fd00::/8) for additional addresses."
            )

        # Map overflow to fd00::/8 range
        # overflow 1 (counter 65536) -> fd00::0:1
        # overflow 65536 (counter 131071) -> fd00::1:0
        #
        # Split the overflow across two hextets. The previous form was
        # ((overflow - 1) % 0x10000) + 1, which ranges 1..0x10000 - one past
        # what a hextet can hold - so every 65536th value produced a five-digit
        # group and an unparseable address (fd00::0:10000).
        overflow = counter - 0xFFFF
        hextet2 = overflow // 0x10000
        hextet3 = overflow % 0x10000
        return f"fd00::{hextet2:x}:{hextet3:x}"

    def _warn_ipv4_limit(self, counter: int) -> None:
        """Warn as the RFC 5737 pool is approached and exhausted"""
        if counter == 700:
            self.logger.warning(
                "[!] Warning: Approaching RFC 5737 IPv4 limit (700/762 addresses used). "
                "Consider reducing unique IPs or using IPv6."
            )
        elif counter == 750:
            self.logger.warning(
                "[!] Warning: Near RFC 5737 IPv4 limit (750/762 addresses used)."
            )
        elif counter == 762:
            self.logger.warning(
                "[!] Warning: Reached RFC 5737 IPv4 limit (762/762 addresses used). "
                "Next IP will use RFC 1918 private range."
            )

    def _counter_to_rfc_ipv4(self, counter: int) -> str:
        """Map a counter into the RFC 5737 ranges, then RFC 1918 on overflow

        RFC 5737 IPv4 documentation ranges (762 total addresses):
        - 192.0.2.0/24 (TEST-NET-1): 254 usable (.1 to .254)
        - 198.51.100.0/24 (TEST-NET-2): 254 usable (.1 to .254)
        - 203.0.113.0/24 (TEST-NET-3): 254 usable (.1 to .254)
        """
        self._warn_ipv4_limit(counter)

        if counter <= 254:
            # First range: 192.0.2.1 to 192.0.2.254
            return f"192.0.2.{counter}"
        if counter <= 508:
            # Second range: 198.51.100.1 to 198.51.100.254
            return f"198.51.100.{counter - 254}"
        if counter <= 762:
            # Third range: 203.0.113.1 to 203.0.113.254
            return f"203.0.113.{counter - 508}"

        # Overflow: use RFC 1918 private range (10.0.0.0/8) for additional addresses
        # This prevents duplicate mappings whilst maintaining valid IP addresses
        # Log warning on first overflow
        if counter == 763:
            self.logger.warning(
                "[!] Warning: Exceeded RFC 5737 IPv4 limit (762 addresses). "
                "Using RFC 1918 private range (10.0.0.0/8) for additional addresses. "
                "This maintains unique mappings but IPs are no longer documentation addresses."
            )

        # Map overflow addresses to 10.0.0.0/8 range
        # Start at 10.0.0.1 for counter 763 (overflow 1)
        overflow = counter - 762

        # Treat the 10.0.0.0/8 space as a flat 24-bit address space
        # Map overflow 1-16777216 to 10.0.0.1-10.255.255.255
        offset = overflow - 1  # Make it 0-based (0 maps to 10.0.0.1)

        # Standard IP octet calculation
        octet2 = offset // 65536
        octet3 = (offset // 256) % 256
        octet4 = (offset % 256) + 1

        # Handle wrap at octet boundaries
        if octet4 > 255:
            octet4 = 0
            octet3 += 1
        if octet3 > 255:
            octet3 = 0
            octet2 += 1

        # Ensure we stay within 10.0.0.0/8 (16,777,216 addresses)
        if octet2 > 255:
            self.logger.error(
                "[!] Error: Exceeded maximum IP address space (762 RFC + 16,777,216 private = 16,777,978 total). "
                "Cannot generate unique IP for counter %d.", counter
            )
            # Return a marker IP to indicate overflow
            return "10.255.255.255"

        return f"10.{octet2}.{octet3}.{octet4}"

    def _anonymise_ip_for_url(self, ip_str: str, is_ipv6: bool) -> str:
        """Generate RFC documentation IP for URL contexts

        Unlike _anonymise_ip which returns IP_n format for bare text,
        this returns valid RFC documentation IPs suitable for URL hosts.

        Args:
            ip_str: The original IP address string
            is_ipv6: True if this is an IPv6 address

        Returns:
            str: RFC documentation IP address
        """
        # Reuse the same counter as _anonymise_ip for consistency
        if ip_str not in self.ip_aliases:
            self.ip_counter += 1
            self.ip_aliases[ip_str] = f"IP_{self.ip_counter}"

        # Extract counter from THIS IP's alias (e.g., "IP_5" -> 5)
        alias = self.ip_aliases[ip_str]
        counter = int(alias.split('_')[1])
        rfc_ip = self._counter_to_rfc_ip(counter, is_ipv6)

        # Mark RFC IP as allowed so we don't re-process it (defence in depth)
        # This prevents re-redaction on subsequent runs
        try:
            self.allowlist_ip_addrs.add(ipaddress.ip_address(rfc_ip))
        except ValueError:
            pass  # Should never happen with valid RFC IPs, but be defensive

        return rfc_ip

    def _validate_and_strip_port(self, token: str) -> tuple[str, str]:
        """Validate and strip port from IPv4 address token.

        Returns:
            tuple: (token_without_port, port_suffix) where port_suffix includes colon
        """
        m_port = re.match(r'^(.*?):(\d+)$', token)
        if not m_port:
            return token, ''

        potential_ip, port_str = m_port.group(1), m_port.group(2)
        try:
            port_num = int(port_str)
        except ValueError:
            return token, ''

        # Validate port range (1-65535)
        if not 1 <= port_num <= 65535:
            return token, ''

        # Only treat as port if it's a valid IPv4 address
        if '.' not in potential_ip:
            return token, ''

        try:
            ipaddress.ip_address(potential_ip)
            return potential_ip, f':{port_num}'
        except ValueError:
            return token, ''

    def _strip_ip_token_port(self, token: str) -> tuple[str, str]:
        """Split a trailing port off an IP token. Returns (token, port_suffix)

        Handles both unbracketed IPv4 (1.2.3.4:80) and bracketed IPv6 with an
        optional zone identifier ([fe80::1%em0]:51820). An out-of-range or
        non-numeric port is left attached, so the token simply fails to parse
        as an address and is returned unchanged by the caller.
        """
        # IPv6 must use brackets to carry a port; only peel :port when unbracketed
        if not token.startswith('['):
            return self._validate_and_strip_port(token)

        if ']:' not in token:
            return token, ''

        bracket_end = token.index(']:')
        port_str = token[bracket_end + 2:]

        try:
            port_num = int(port_str)
        except ValueError:
            return token, ''

        if not 1 <= port_num <= 65535:
            return token, ''

        return token[:bracket_end + 1], f':{port_num}'

    def _should_preserve_ip(self, ip: IPAddress) -> bool:
        """Check whether an address should be left as-is rather than masked"""
        # Common netmasks and unspecified addresses stay readable regardless of
        # --keep-private-ips
        if str(ip) in self.always_preserve_ips:
            return True

        # Allow-listed IPs (opt-in, including CIDR networks)
        if self._is_ip_allowed(ip):
            return True

        # In anonymise mode, RFC documentation IPs are our own generated values
        if self.anonymise and is_rfc_documentation_ip(ip):
            return True

        # Non-global addresses if requested: RFC1918, ULA, loopback, link-local,
        # multicast, reserved and unspecified
        return self.keep_private_ips and not ip.is_global

    def _mask_one_ip_token(self, token: str) -> str:
        """Mask a single IP-like token, or return it unchanged

        A method rather than a closure inside _mask_ip_like_tokens: it uses
        nothing but self and its argument, and analysers that fold nested
        functions into their parent counted the whole thing as one oversized
        unit.
        """
        # Skip already-masked tokens
        if token in MASKED_IP_TOKENS:
            return token
        original_token = token

        token, port_suffix = self._strip_ip_token_port(token)

        ip, bracketed, zone = self._parse_ip_token(token)
        if ip is None:
            return original_token

        if self._should_preserve_ip(ip):
            return original_token

        rep = self._ip_replacement(ip)
        result = self._restore_token_shape(rep, zone, bracketed) + port_suffix

        # Only count if actually changed
        if result != original_token:
            self.stats['ips_redacted'] += 1
            # Collect sample for dry-run-verbose
            self._add_sample('IP', str(ip), rep)

        return result

    def _ip_replacement(self, ip: IPAddress) -> str:
        """The masked form of one address, honouring --anonymise"""
        if self.anonymise:
            return self._anonymise_ip(str(ip))
        return MASKED_IPV4 if ip.version == 4 else MASKED_IPV6

    @staticmethod
    def _restore_token_shape(rep: str, zone: str | None, bracketed: bool) -> str:
        """Put back the zone identifier and brackets the token arrived with

        Both are structure rather than address, so they survive redaction: a
        zone id names a local interface and brackets are what make an IPv6
        literal parseable inside a netloc.
        """
        if zone:
            rep = f"{rep}%{zone}"
        if bracketed:
            rep = f"[{rep}]"
        return rep

    def _mask_ip_like_tokens(self, text: str) -> str:
        """IP address masking using ipaddress module"""
        # Split conservatively - matches IP-like tokens including zone IDs and ports
        # Pattern matches: IPs with optional brackets, zone identifiers, and ports
        # Examples: [fe80::1%eth0]:51820, [fe80::1%eth0], fe80::1%eth0, 192.168.1.1
        parts = self._ip_token_splitter.split(text)
        # Match tokens that look like IPs (with or without brackets/zones/ports)
        # Use pre-compiled pattern for consistency and performance
        return ''.join(
            self._mask_one_ip_token(p) if self.IP_PATTERN.match(p) else p
            for p in parts
        )

    def _anonymise_domain(self, domain: str) -> str:
        """Generate a consistent alias for a domain

        Normalises to IDNA (punycode) to ensure Unicode and ASCII forms
        of the same domain get the same alias (e.g., bücher.de and xn--bcher-kva.de)
        """
        # Normalise domain to ensure consistent aliases (lowercase, strip trailing dots)
        raw = domain.rstrip('.').lower()

        # Convert to IDNA (punycode) for consistent aliasing across Unicode/ASCII forms
        norm = _idna_encode(raw)

        if norm not in self.domain_aliases:
            self.domain_counter += 1
            self.domain_aliases[norm] = f"domain{self.domain_counter}.example"
        return self.domain_aliases[norm]

    def _parse_url_safely(self, url: str) -> SplitResult | None:
        """Parse URL, returning None if parsing fails"""
        try:
            return urlsplit(url)
        except ValueError:
            return None

    def _is_already_masked_host(self, host: str) -> bool:
        """Check if hostname is already a masked value

        Recognises:
        - Standard redaction masks (XXX.XXX.XXX.XXX, etc.)
        - Anonymisation domain aliases (domain1.example, etc.)
        - RFC documentation IPs (only in anonymise mode - these are our generated values)
        """
        if host in ('XXX.XXX.XXX.XXX',
                    'XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX',
                    'example.com'):
            return True

        # Check for anonymisation domain aliases
        if self.anonymise and re.fullmatch(r'domain\d+\.example', host):
            return True

        # In anonymise mode, RFC documentation IPs are masked values (generated by us)
        # In non-anonymise mode, RFC IPs in original configs should still be redacted
        if self.anonymise:
            try:
                if is_rfc_documentation_ip(ipaddress.ip_address(host)):
                    return True
            except ValueError:
                pass  # Not an IP

        return False

    def _normalise_masked_url(self, parts: SplitResult, host: str) -> str:
        """Normalise already-masked URLs to use example.com (or alias in anonymise mode)

        Note: RFC documentation IPs are preserved in anonymise mode (they're our generated values)
        """
        # An already-masked host says nothing about the rest of the URL: the
        # query and userinfo beside it still need scrubbing, so every branch
        # below goes through these rather than returning parts untouched.
        query = self._redact_query_secrets(parts.query)

        # Whether the host is already masked and should be kept as-is
        keep_host = False

        # In anonymise mode, RFC documentation IPs are our own generated values
        if self.anonymise:
            try:
                keep_host = is_rfc_documentation_ip(ipaddress.ip_address(host))
            except ValueError:
                pass  # Not an IP, continue with domain normalisation

        # In anonymise mode, use a consistent alias for masked URLs
        masked_host = self._anonymise_domain('example.com') if self.anonymise else 'example.com'

        if keep_host or host == masked_host:
            netloc, _ = self._redact_netloc_userinfo(parts)
        else:
            # Replace IP masks with example.com (or alias)
            netloc = self._build_netloc(parts, masked_host, False)

        return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))

    def _mask_url_host(self, host: str) -> tuple[str, bool, bool]:
        """Mask URL host. Returns (masked_host, changed, is_ipv6)"""
        # Check if already masked (including RFC documentation IPs)
        if self._is_already_masked_host(host):
            # Determine if it's IPv6 for proper bracket handling
            try:
                ip = ipaddress.ip_address(host)
                return host, False, ip.version == 6
            except ValueError:
                return host, False, False

        # Try as IP address
        try:
            ip = ipaddress.ip_address(host)
            return self._mask_ip_host(ip)
        except ValueError:
            # Treat as domain
            return self._mask_domain_host(host)

    def _mask_ip_host(self, ip: IPAddress) -> tuple[str, bool, bool]:
        """Mask IP address in URL. Returns (masked, changed, is_ipv6)"""
        is_ipv6 = ip.version == 6

        # Check preservation rules
        if str(ip) in self.always_preserve_ips:
            return str(ip), False, is_ipv6

        if self._is_ip_allowed(ip):
            return str(ip), False, is_ipv6

        if self.keep_private_ips and not ip.is_global:
            return str(ip), False, is_ipv6

        # Mask the IP
        if self.anonymise:
            # Use RFC documentation IPs for URL hosts (parseable)
            masked = self._anonymise_ip_for_url(str(ip), is_ipv6)
        else:
            masked = 'example.com' if ip.version == 4 else 'XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX'

        self.stats['ips_redacted'] += 1
        return masked, True, is_ipv6

    def _mask_domain_host(self, host: str) -> tuple[str, bool, bool]:
        """Mask domain in URL. Returns (masked, changed, is_ipv6=False)"""
        if self._is_domain_allowed(host):
            return host, False, False

        masked = self._anonymise_domain(host) if self.anonymise else 'example.com'
        return masked, True, False

    @staticmethod
    def _needs_ipv6_brackets(host: str, is_ipv6: bool) -> bool:
        """Whether a host must be bracketed to be a valid URL netloc

        A colon in an unbracketed host means IPv6 even when the caller did not
        already know it, which is why the flag alone is not enough.
        """
        return is_ipv6 or (':' in host and not host.startswith('['))

    def _build_userinfo(self, parts: SplitResult) -> str:
        """Build the 'user:pass@' prefix of a netloc, redacting as configured

        The password is always replaced; the username only under
        --redact-url-usernames, since it is often an ordinary account name that
        is more useful left readable.
        """
        if not parts.username:
            return ''

        username = 'REDACTED' if self.redact_url_usernames else parts.username
        password = ':REDACTED' if parts.password else ''
        return f"{username}{password}@"

    def _build_netloc(self, parts: SplitResult, host: str, is_ipv6: bool) -> str:
        """Build netloc with userinfo, host, and port"""
        userinfo = self._build_userinfo(parts)

        # Wrap IPv6 in brackets
        if self._needs_ipv6_brackets(host, is_ipv6):
            host = f"[{host}]"

        netloc = f"{userinfo}{host}"

        # Handle port - parts.port can raise ValueError for invalid ports
        try:
            if parts.port:
                netloc += f":{parts.port}"
        except ValueError:
            # Invalid port detected (out of range or non-numeric)
            # Omit port to ensure output URL is valid
            # Log at debug level as this is uncommon but not critical
            self.logger.debug(
                "Invalid port in URL netloc, omitting: %s",
                parts.netloc
            )
            # Don't append anything - netloc is valid without port

        return netloc

    @staticmethod
    def _build_redacted_query(query: str) -> tuple[str, bool]:
        """Build a query string with secret-named parameter values redacted

        Returns (query, changed). Pure: no statistics side effects, so the
        --dry-run-verbose sample display can reuse it without inflating the
        redaction counters.
        """
        if not query:
            return query, False

        try:
            pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
        except ValueError:
            return query, False

        if not pairs:
            return query, False

        changed = False
        out = []
        for name, value in pairs:
            name_l = name.lower()
            if _is_secret_query_param(name_l, value):
                out.append((name, '[REDACTED]'))
                changed = True
            else:
                out.append((name, value))

        if not changed:
            return query, False

        return urlencode(out), True

    def _redact_query_secrets(self, query: str) -> str:
        """Redact query-parameter values whose parameter name names a secret

        Anonymising the host while leaving '?token=...' intact gives false
        reassurance: the credential is still there in full. DynDNS update URLs
        and licenced feed URLs both put the secret in the query string.
        """
        redacted, changed = self._build_redacted_query(query)
        if changed:
            self.stats['url_secrets_redacted'] += 1
        return redacted

    @staticmethod
    def _is_secretish_token(part: str) -> bool:
        """Whether one colon-separated piece of a path segment is a credential

        Uses a lower length floor than _is_high_entropy_value: webhook tokens
        sit around 20-24 chars, below the threshold used for key material.

        Every boundary here is load-bearing, so each is justified:

        - >= 20, not > 20. AWS access key IDs (AKIA...) are exactly 20
          characters, so a > 20 test excluded the entire format.
        - A digit is required only below DIGITLESS_TOKEN_LENGTH. The digit rule
          exists to protect underscore-joined route names such as
          'Open_VM_Tools_package' (21 chars); beyond that length an all-letter
          segment is far more likely to be a token than a route. Requiring a
          digit unconditionally silently missed alphabetic Slack tokens.
        """
        if len(part) < SECRETISH_SEGMENT_MIN_LENGTH:
            return False
        if not BASE64ISH_RE.match(part):
            return False
        if not any(c.isalpha() for c in part):
            return False

        if any(c.isdigit() for c in part):
            return True
        return len(part) >= DIGITLESS_TOKEN_LENGTH

    @classmethod
    def _is_secretish_path_segment(cls, segment: str) -> bool:
        """Check whether a URL path segment looks like an embedded credential

        Split on colons before testing. Telegram bot tokens are
        'bot<id>:<secret>', and the colon fails BASE64ISH_RE, which let a
        47-character credential through as an ordinary path segment.
        """
        return any(cls._is_secretish_token(part) for part in segment.split(':'))

    @classmethod
    def _build_redacted_path(cls, path: str) -> tuple[str, bool]:
        """Build a path with credential-shaped segments redacted

        Returns (path, changed). Pure, for the same reason as
        _build_redacted_query.
        """
        if not path or '/' not in path:
            return path, False

        segments = path.split('/')
        changed = False
        for i, segment in enumerate(segments):
            if cls._is_secretish_path_segment(segment):
                segments[i] = '[REDACTED]'
                changed = True

        if not changed:
            return path, False

        return '/'.join(segments), True

    def _redact_path_secrets(self, path: str) -> str:
        """Redact long high-entropy path segments

        Slack/Discord-style webhooks carry the credential as a path segment
        rather than a query parameter. Callers decide when to apply this - see
        _should_redact_path.
        """
        redacted, changed = self._build_redacted_path(path)
        if changed:
            self.stats['url_secrets_redacted'] += 1
        return redacted

    def _should_redact_path(self, parts: SplitResult) -> bool:
        """Whether this URL's path should be scanned for embedded credentials

        Aggressive mode scans every path. Otherwise only known webhook
        endpoints, where the path token is the whole authorisation and the host
        identifies it unambiguously - so it is worth redacting without waiting
        for an opt-in flag.
        """
        if self.aggressive:
            return True
        return _is_webhook_url(parts.hostname or '', parts.path)

    def _redact_path_if_needed(self, parts: SplitResult) -> str:
        """Return the path, credential segments redacted where that applies"""
        if self._should_redact_path(parts):
            return self._redact_path_secrets(parts.path)
        return parts.path

    def _rebuild_url(self, parts: SplitResult, masked_host: str, is_ipv6: bool) -> str:
        """Rebuild URL from parts with masked host"""
        netloc = self._build_netloc(parts, masked_host, is_ipv6)

        path = self._redact_path_if_needed(parts)
        query = self._redact_query_secrets(parts.query)

        # Manual construction for masked IPv6 (urlunsplit doesn't like invalid IPv6)
        if is_ipv6 and 'XXXX:XXXX' in masked_host:
            result = f"{parts.scheme}://{netloc}{path}"
            if query:
                result += f"?{query}"
            if parts.fragment:
                result += f"#{parts.fragment}"
            return result

        return urlunsplit((parts.scheme, netloc, path, query, parts.fragment))

    def _mask_url(self, url: str) -> str:
        """Mask URL hostname whilst preserving structure, credentials, and port"""
        parts = self._parse_url_safely(url)
        if parts is None:
            return url

        host = parts.hostname or ''

        # Skip URLs without hostnames (e.g., file:///path, about:blank)
        # These have no network location to redact and no credentials to leak
        if not host:
            return url

        # Check if already masked
        if self._is_already_masked_host(host):
            return self._normalise_masked_url(parts, host)

        # Determine host type and mask accordingly
        masked_host, host_changed, is_ipv6 = self._mask_url_host(host)

        # Rebuild URL
        result = self._rebuild_url(parts, masked_host, is_ipv6)

        # Track statistics
        if host_changed and result != url:
            self.stats['urls_redacted'] += 1
            self._add_sample('URL', url, result)

        return result

    def _redact_netloc_userinfo(self, parts: SplitResult) -> tuple[str, bool]:
        """Redact credentials in a URL's userinfo, leaving the host untouched

        Returns (netloc, changed).

        The host portion is sliced from the original netloc rather than taken
        from parts.hostname, because the latter lower-cases it - this function
        must not alter the host in any way.
        """
        if not parts.username:
            return parts.netloc, False

        host_port = parts.netloc.rsplit('@', 1)[-1]

        # Same policy as _build_netloc: usernames are preserved unless asked
        # for, passwords are always redacted.
        userinfo = 'REDACTED' if self.redact_url_usernames else parts.username
        if parts.password:
            userinfo += ':REDACTED'

        netloc = f"{userinfo}@{host_port}"
        return netloc, netloc != parts.netloc

    def _redact_url_secrets_only(self, text: str) -> str:
        """Redact credentials inside URLs without touching the host

        Used for elements that are not known URL carriers. Those elements only
        get host anonymisation under --aggressive, and widening that to the
        default path would rewrite harmless package metadata URLs (package
        <website>, <pkginfolink>) for no security benefit. The embedded
        credential is the part that matters, so redact just that.

        Userinfo is redacted here as well as in _build_netloc: omitting it left
        'user:password@host' intact while the query secret next to it showed as
        [REDACTED], which reads as sanitised when it is not.
        """
        return self.URL_RE.sub(self._redact_url_secrets_in_match, text)

    def _redact_url_secrets_in_match(self, match) -> str:
        """Redact credentials in one matched URL, leaving the host alone

        A method rather than a closure, for the same reason as
        _mask_one_ip_token: it needs only self and the match.
        """
        url = match.group(0)
        if len(url) > self.MAX_URL_LENGTH:
            return url

        parts = self._parse_url_safely(url)
        if parts is None or not parts.netloc:
            return url

        netloc, netloc_changed = self._redact_netloc_userinfo(parts)
        path = self._redact_path_if_needed(parts)
        query = self._redact_query_secrets(parts.query)

        if self._url_parts_unchanged(parts, netloc_changed, path, query):
            return url

        if netloc_changed:
            self.stats['url_secrets_redacted'] += 1

        return urlunsplit((parts.scheme, netloc, path, query, parts.fragment))

    @staticmethod
    def _url_parts_unchanged(parts: SplitResult, netloc_changed: bool,
                             path: str, query: str) -> bool:
        """Whether redaction left the URL identical, so it can be returned as-is

        netloc_changed must be part of this test: a URL carrying credentials but
        no secret-named query parameter would otherwise never be rewritten.
        """
        return not netloc_changed and path == parts.path and query == parts.query

    def _redact_urls_safe(self, text: str) -> str:
        """Redact URLs with ReDoS protection via length pre-filtering"""
        def url_replacer(match):
            url = match.group(0)
            # Pre-filter: Skip obviously too-long URLs
            if len(url) > self.MAX_URL_LENGTH:
                return url  # Too long, don't process
            return self._mask_url(url)

        # Use re.sub directly to preserve whitespace
        return self.URL_RE.sub(url_replacer, text)

    def _redact_emails_safe(self, text: str) -> str:
        """Redact emails with ReDoS protection via length pre-filtering"""
        def email_mask_safe(match):
            email = match.group(0)
            # Pre-filter: Skip obviously too-long emails
            if len(email) > self.MAX_EMAIL_LENGTH:
                return email  # Don't process suspiciously long "emails"

            self.stats['emails_redacted'] += 1
            if self.anonymise:
                domain = email.split('@')[1]
                token = self._anonymise_domain(domain)
                return f'user@{token}'
            return 'user@example.com'

        # Use re.sub directly to preserve whitespace
        return self.EMAIL_RE.sub(email_mask_safe, text)

    def _stash_urls(self, text: str) -> tuple[str, list[str]]:
        """Replace URLs with placeholders so later passes cannot rewrite them

        Returns (text, stashed). URLs have already been handled by
        _mask_url/_redact_url_secrets_only by this point; without stashing, the
        FQDN pass matches filenames inside the path ('/lists/list.txt') and
        rewrites them to example.com.
        """
        stashed: list[str] = []

        def keep(match: re.Match) -> str:
            stashed.append(match.group(0))
            return f'\x00URL{len(stashed) - 1}\x00'

        return self.URL_RE.sub(keep, text), stashed

    @staticmethod
    def _restore_urls(text: str, stashed: list[str]) -> str:
        """Put stashed URLs back after later passes have run

        A single regex pass rather than one str.replace per URL: the latter
        rescans the whole text for every stashed URL, which is O(urls x text).
        Measured at ~140x slower with 200 URLs in a large element.
        """
        if not stashed:
            return text

        def restore(match: re.Match) -> str:
            index = int(match.group(1))
            # Out of range is unreachable (NUL cannot appear in XML content, so
            # every placeholder is one we wrote), but return the match rather
            # than raising if that ever stops being true.
            return stashed[index] if index < len(stashed) else match.group(0)

        return URL_PLACEHOLDER_RE.sub(restore, text)

    def _redact_fqdns_safe(self, text: str) -> str:
        """Redact FQDNs with ReDoS protection via length pre-filtering"""
        def fqdn_mask_safe(match):
            domain = match.group(0)
            # Pre-filter: Skip obviously too-long domains
            if len(domain) > self.MAX_FQDN_LENGTH:
                return domain  # Don't process suspiciously long "domains"

            # A filesystem or URL path component, not a hostname. Checked by
            # context because the extension alone cannot decide it: '.sh' is
            # both a shell script and Saint Helena's TLD.
            if match.start() > 0 and text[match.start() - 1] == '/':
                return domain

            # Unambiguous file extension: 'list.txt', 'backup-2026.tar.gz'
            if domain.rsplit('.', 1)[-1].lower() in FILE_EXTENSIONS:
                return domain

            if self._is_domain_allowed(domain):
                return domain

            replacement = self._anonymise_domain(domain) if self.anonymise else 'example.com'
            if replacement != domain:
                self.stats['domains_redacted'] += 1
                self._add_sample('FQDN', domain, replacement)
            return replacement

        # Use re.sub directly to preserve whitespace
        return self.FQDN_RE.sub(fqdn_mask_safe, text)

    def redact_text(self, text: str, redact_ips: bool = True, redact_domains: bool = True) -> str:
        """Redact sensitive patterns from text"""
        if not text:
            return text

        # ReDoS protection - reject absurdly long text chunks
        if len(text) > self.MAX_TEXT_CHUNK:
            # Log warning and truncate
            self.logger.warning("[!] Warning: Text chunk too long (%d chars), truncating", len(text))
            text = text[:self.MAX_TEXT_CHUNK]

        result = text

        # Redact MAC addresses FIRST (both formats) before IP processing
        # This prevents strings like aa:bb:cc:dd:ee:ff from being misinterpreted as IPv6
        std_macs = self.MAC_RE.findall(result)
        cisco_macs = self.MAC_CISCO_RE.findall(result)

        # Collect samples for dry-run-verbose
        for mac in std_macs[:self.sample_limit]:
            self._add_sample('MAC', mac, 'XX:XX:XX:XX:XX:XX')
        for mac in cisco_macs[:self.sample_limit]:
            self._add_sample('MAC', mac, 'XXXX.XXXX.XXXX')

        self.stats['macs_redacted'] += len(std_macs) + len(cisco_macs)

        result = self.MAC_RE.sub('XX:XX:XX:XX:XX:XX', result)
        result = self.MAC_CISCO_RE.sub('XXXX.XXXX.XXXX', result)

        if redact_domains:
            # Redact URLs FIRST before bare IPs (to preserve URL structure)
            # Note: _mask_url now handles its own counting
            result = self._redact_urls_safe(result)

        # Redact IP addresses (robust) - done after URLs to avoid breaking URL structure
        if redact_ips:
            result = self._mask_ip_like_tokens(result)

        if redact_domains:
            # Redact emails with ReDoS protection
            result = self._redact_emails_safe(result)

            # Protect IPv4 mask and Cisco MAC format before FQDN pass
            # (prevent XXX.XXX.XXX.XXX → example.com and XXXX.XXXX.XXXX → example.com)
            ipv4_mask_placeholder = '___IPV4_MASK_PLACEHOLDER___'
            cisco_mac_placeholder = '___CISCO_MAC_PLACEHOLDER___'
            result = result.replace('XXX.XXX.XXX.XXX', ipv4_mask_placeholder)
            result = result.replace('XXXX.XXXX.XXXX', cisco_mac_placeholder)

            # Protect URLs for the same reason. Their hosts were already masked
            # by _redact_urls_safe above; leaving them exposed to the FQDN pass
            # rewrote filenames in the path (/lists/list.txt -> /lists/
            # example.com), which corrupts the output rather than redacting it.
            result, stashed_urls = self._stash_urls(result)

            # Redact remaining bare FQDNs with ReDoS protection
            result = self._redact_fqdns_safe(result)

            # Restore URLs, IPv4 mask and Cisco MAC format
            result = self._restore_urls(result, stashed_urls)
            result = result.replace(ipv4_mask_placeholder, 'XXX.XXX.XXX.XXX')
            result = result.replace(cisco_mac_placeholder, 'XXXX.XXXX.XXXX')

        return result

    def _normalise_tag(self, tag: str) -> str:
        """Normalise tag name to handle namespaced exports"""
        return tag.rsplit('}', 1)[-1].lower()

    def _get_tag_base(self, tag: str) -> str:
        """Strip trailing digits from tag (e.g., dnsserver6 -> dnsserver)"""
        return re.sub(r'\d+$', '', tag)

    def _redact_text_and_track(
        self, element: ET.Element, category: str, replacement: str = '[REDACTED]'
    ) -> None:
        """Redact element text and track statistics"""
        original = element.text
        element.text = replacement

        if category == 'Cert/Key':
            self.stats['certs_redacted'] += 1
        else:
            self.stats['secrets_redacted'] += 1

        self._add_sample(category, original, replacement)

    def _is_secret_tag(self, tag: str, tag_base: str) -> bool:
        """Check whether a tag names a secret-bearing element

        Matches in three ways:
        1. Exact membership of REDACT_ELEMENTS (tag or digit-stripped base)
        2. SECRET_TAG_PATTERN substring match, unless deny-listed

        The digit-stripped base handles numbered variants (password2, key3).
        """
        if tag in self.redact_elements or tag_base in self.redact_elements:
            return True

        if tag in SECRET_TAG_DENYLIST or tag_base in SECRET_TAG_DENYLIST:
            return False

        return bool(SECRET_TAG_PATTERN.search(tag) or SECRET_TAG_PATTERN.search(tag_base))

    def _is_cert_tag(self, tag: str, tag_base: str) -> bool:
        """Check whether a tag names a certificate/key-bearing element"""
        if tag in self.cert_key_elements or tag_base in self.cert_key_elements:
            return True

        if tag in SECRET_TAG_DENYLIST or tag_base in SECRET_TAG_DENYLIST:
            return False

        return bool(CERT_TAG_PATTERN.search(tag) or CERT_TAG_PATTERN.search(tag_base))

    @staticmethod
    def _names_an_algorithm_choice(tag: str, tag_base: str, element: ET.Element) -> bool:
        """Whether a digest/hash element selects an algorithm rather than holding one's output

        <digest>SHA384</digest> is IPsec choosing an algorithm; the reader needs
        it and it is not a secret. <digest>CANARY_ADV19_DIGEST</digest> in the
        same element name is. Only the closed ALGORITHM_VALUE_NAMES list is
        preserved, so anything unrecognised is still treated as a secret.
        """
        if tag not in ALGORITHM_NAMED_ELEMENTS and tag_base not in ALGORITHM_NAMED_ELEMENTS:
            return False
        if len(element) > 0:
            return False

        value = (element.text or '').strip().lower()
        return not value or value in ALGORITHM_VALUE_NAMES

    def _should_redact_completely(self, tag: str, tag_base: str, element: ET.Element) -> bool:
        """Check if element should be completely redacted and handle it. Returns True if handled."""
        if not self._is_secret_tag(tag, tag_base):
            return False

        if self._names_an_algorithm_choice(tag, tag_base, element):
            return False

        if element.text:
            self._redact_text_and_track(element, 'Secret')

        # Redact attributes
        for attr in list(element.attrib.keys()):
            original = element.attrib[attr]
            element.attrib[attr] = '[REDACTED]'
            self.stats['secrets_redacted'] += 1
            self._add_sample('Secret', original, '[REDACTED]')

        # Process children recursively
        for child in element:
            self.redact_element(child)

        return True

    def _looks_like_secret_blob(self, text: str) -> bool:
        """Check whether text looks like PEM or long base64/hex key material

        Uses the class length constants. Previously inlined in the <key> handler;
        extracted so unrecognised elements can be screened with the same rules.
        """
        if not text:
            return False

        return bool(
            self.PEM_MARKER.search(text) or
            len(text) >= self.KEY_BLOB_MIN_LENGTH or
            (len(text) > self.KEY_SHORT_THRESHOLD and
             text.replace('\n', '').replace('\r', '').replace(' ', '').isalnum())
        )

    def _is_high_entropy_value(self, text: str) -> bool:
        """Check whether a leaf value looks like an encoded secret

        Three classes, in descending order of certainty:

        1. private-key material, including through a bounded decode
        2. a compact JWT
        3. an opaque shape - the only heuristic of the three

        The first two are structural facts about the value rather than
        judgements about it, so they are checked before the length floor: a
        value can be shorter than BLOB_MIN_SCAN_LENGTH and still be a key
        header or a token.

        The complete predicate, and the one to call when nothing is known about
        the value. A caller that has *already* ruled out cases 1 and 2 should
        call _is_opaque_value instead: repeating them here costs a second
        bounded decode of the same text, which is the expensive half.
        """
        if unambiguous_secret_kind(text) is not None:
            return True
        return self._is_opaque_value(text)

    def _is_opaque_value(self, text: str) -> bool:
        """Case 3 alone: whether the value is shaped like an opaque secret

        Stricter than _looks_like_secret_blob: the whole value must be
        base64/hex-shaped, so ordinary long prose is not flagged.
        """
        if len(text) < BLOB_MIN_SCAN_LENGTH:
            return False

        if self.PEM_MARKER.search(text):
            return True

        # Strip line wrapping only. Spaces must NOT be stripped: doing so turns
        # ordinary prose ("This is a fairly long note") into an unbroken
        # alphanumeric run that looks exactly like base64.
        compact = text.replace('\n', '').replace('\r', '')
        if _disqualified_as_blob(compact):
            return False

        return _is_opaque_secret_shape(compact)

    def _redact_blob_text_element(self, tag: str, tag_base: str, element: ET.Element) -> bool:
        """Scan opaque free-text containers for inline credentials

        Returns True if the element's text was processed.
        """
        if tag not in BLOB_TEXT_ELEMENTS and tag_base not in BLOB_TEXT_ELEMENTS:
            return False
        if not element.text or not element.text.strip():
            return False

        if self.aggressive:
            # Under --aggressive these blobs are redacted wholesale - their
            # contents are unparseable in general and may carry secrets in
            # forms no scanner will recognise.
            self._redact_text_and_track(element, 'Secret')
            return True

        original = element.text
        redacted = self._redact_blob_text_and_urls(original)

        if redacted != original:
            element.text = redacted
            self.stats['secrets_redacted'] += 1
            self._add_sample('Secret', original, redacted)
        return True

    @staticmethod
    def _is_secret_key_name(name: str) -> bool:
        """Check whether a key/directive name inside blob text denotes a secret"""
        name_l = name.lower()
        if name_l in BLOB_SECRET_DIRECTIVES:
            return True
        if name_l in SECRET_TAG_DENYLIST:
            return False
        return bool(SECRET_TAG_PATTERN.search(name_l))

    def _redact_blob_text_and_urls(self, text: str) -> str:
        """Scan blob text for both inline key=value credentials and URL secrets

        This element reports its text as handled, which suppresses the
        URL-secret pass in redact_element; without running it here, blob
        elements would get LESS URL scanning than an unrecognised element.

        The two scanners must not see each other's output. Running the KV scan
        over an already-redacted URL re-encodes the '[REDACTED]' marker and
        leaves a stray bracket behind, so URL spans are stashed behind
        placeholders while the KV scan runs - the same technique redact_text()
        uses to protect IPv4 masks from the FQDN pass.
        """
        if '://' not in text:
            return self._redact_blob_text(text)

        stashed_text, stashed = self._stash_urls(self._redact_url_secrets_only(text))
        return self._restore_urls(self._redact_blob_text(stashed_text), stashed)

    def _redact_blob_text(self, text: str) -> str:
        """Redact the value side of key=value pairs and secret-bearing directives"""
        out = []
        for line in text.splitlines(keepends=True):
            stripped = line.rstrip('\r\n')
            newline = line[len(stripped):]

            # 'askpass /path/to/file' style directives, whose name carries the
            # meaning rather than the argument
            directive = BLOB_DIRECTIVE_RE.match(stripped)
            if directive and directive.group('key').lower() in BLOB_SECRET_DIRECTIVES:
                out.append(
                    f"{directive.group('indent')}{directive.group('key')}"
                    f"{directive.group('sep')}[REDACTED]{newline}"
                )
                continue

            # key=value / key: value pairs anywhere in the line
            replaced = BLOB_KV_RE.sub(
                lambda m: (
                    f"{m.group('key')}{m.group('sep')}[REDACTED]"
                    if self._is_secret_key_name(m.group('key')) else m.group(0)
                ),
                stripped
            )
            out.append(replaced + newline)
        return ''.join(out)

    def _redact_description_element(self, tag: str, tag_base: str, element: ET.Element) -> bool:
        """Redact description/identifier free text (opt-in via --redact-descriptions)"""
        if not self.redact_descriptions:
            return False
        if tag not in DESCRIPTION_ELEMENTS and tag_base not in DESCRIPTION_ELEMENTS:
            return False
        if not element.text or not element.text.strip():
            return False

        self._redact_text_and_track(element, 'Secret')
        return True

    def _redact_unambiguous_secret_element(self, element: ET.Element, text: str) -> bool:
        """Remove private-key material or a JWT from element text, in every mode

        These do not depend on the element being recognised, and they are not
        subject to the report-only policy below: a PEM private-key header and a
        compact JWT are unambiguous evidence, so there is no over-redaction risk
        to trade against.
        """
        kind = unambiguous_secret_kind(text)
        if kind is None:
            return False

        category, placeholder = _redaction_for(kind)
        self._redact_text_and_track(element, category, placeholder)
        return True

    def _account_for_opaque_element(self, tag: str, element: ET.Element, text: str) -> bool:
        """Redact or report an opaque value, which is the heuristic half

        Default: record the value's location so users can audit it manually,
        because the false-positive argument genuinely applies to a shapeless
        blob. --aggressive: redact it.
        """
        # _is_opaque_value, not _is_high_entropy_value: the caller has already
        # established the value is not private-key material and not a JWT, and
        # re-checking would decode it a second time.
        if not self._is_opaque_value(text):
            return False

        if self.aggressive:
            self._redact_text_and_track(element, 'Cert/Key', '[REDACTED_CERT_OR_KEY]')
            return True

        # _path_stack holds ancestors only; this element's own tag completes it
        self._record_retained_path('/'.join([*self._path_stack, tag]))
        return False

    def _record_retained_path(self, path: str) -> None:
        """Count a retained high-entropy value and remember where it is"""
        self.stats['high_entropy_retained'] += 1
        if path not in self.high_entropy_paths:
            self.high_entropy_paths.append(path)

    def _redact_unknown_blob_element(self, tag: str, element: ET.Element) -> bool:
        """Handle high-entropy values in elements we do not otherwise recognise

        Two policies, in order, split into a method each because they are
        decided on different grounds:

        1. _redact_unambiguous_secret_element - private-key material and JWTs,
           removed in every mode because the value itself settles the question
        2. _account_for_opaque_element - everything else, where the shape is
           only evidence and report-only remains the default

        The <key> handler already covers its own tag; everything else previously
        sailed through regardless of how much it looked like key material.
        """
        if tag == 'key' or len(element) > 0:
            return False
        if not element.text:
            return False

        text = element.text.strip()
        if self._redact_unambiguous_secret_element(element, text):
            return True
        return self._account_for_opaque_element(tag, element, text)

    def _redact_key_element_if_needed(self, tag: str, element: ET.Element) -> bool:
        """Redact <key> element if needed - can be short secret or PEM blob. Returns True if handled."""
        if tag != 'key' or not element.text:
            return False

        text = element.text.strip()
        if self._looks_like_secret_blob(text):
            self._redact_text_and_track(element, 'Cert/Key', '[REDACTED_CERT_OR_KEY]')
        else:
            # Short key - treat as secret
            self._redact_text_and_track(element, 'Secret')

        # Process children
        for child in element:
            self.redact_element(child)

        return True

    @staticmethod
    def _collect_refids(root: ET.Element) -> frozenset[str]:
        """Every refid defined anywhere in the config

        Collected from the whole tree rather than from <cert>/<ca>/<crl> alone:
        package certificate stores do not reliably sit where the base system
        puts them, and a superset only ever preserves more references.

        Safe to build before redaction and use after it, because <refid> is
        matched by neither SECRET_TAG_PATTERN nor CERT_TAG_PATTERN and its
        13-character values are under BLOB_MIN_SCAN_LENGTH. The ids survive, so
        the references this keeps still resolve in the output.
        """
        return frozenset(
            refid for el in root.iter('refid') if (refid := (el.text or '').strip())
        )

    def _looks_like_cert_material(self, text: str | None) -> bool:
        """Whether an element's text is certificate or key material

        Length is the test only once a PEM header has been ruled out: anything
        longer than a reference id, in an element named for a certificate, is
        the material itself.
        """
        if not text:
            return False
        return bool(self.PEM_MARKER.search(text)) or len(text.strip()) > self.CERT_MIN_LENGTH

    def _is_known_cert_reference(self, text: str) -> bool:
        """Whether a short value in a cert-named element is a reference we can resolve

        The config states which references exist, so resolve against it rather
        than inferring from length. HAProxy's ha_certificates can carry several,
        so every token has to resolve: a partial match means the value is not
        purely a reference list, and the whole of it is then suspect.

        Expects text already stripped by the caller.
        """
        tokens = [t for t in re.split(r'[,\s]+', text) if t]
        if not tokens:
            return False
        return all(token in self.known_refids for token in tokens)

    def _names_a_cert_store(self, tag: str, tag_base: str) -> bool:
        """Whether the tag names a certificate reference or store

        CERT_KEY_ELEMENTS (<crt>, <cert>, <public-key>) carry the material
        itself, so a short value in one of those is a truncated key or one of
        our own placeholders - never a refid, and not something to resolve.
        """
        if tag in self.cert_key_elements:
            return False
        if tag_base in self.cert_key_elements:
            return False
        return bool(CERT_TAG_PATTERN.search(tag) or CERT_TAG_PATTERN.search(tag_base))

    def _holds_unresolvable_cert_reference(self, tag: str, tag_base: str, element: ET.Element) -> bool:
        """Whether a cert-named element holds a short value the config cannot account for"""
        if not self._names_a_cert_store(tag, tag_base):
            return False

        # Containers such as <ha_certificates><item>... have only the newline
        # before their first child as text; treating that as a value would
        # redact the wrapper and swallow the children's indentation.
        #
        # len() rather than a truthiness test on purpose: ElementTree elements
        # with no children are falsy, so 'if element' asks a different question
        # and gets the wrong answer.
        if len(element) > 0:
            return False

        text = (element.text or '').strip()
        if not text:
            return False

        if text in REDACTION_PLACEHOLDERS:
            return False

        return not self._is_known_cert_reference(text)

    def _redact_cert_key_element(self, tag: str, tag_base: str, element: ET.Element) -> bool:
        """Redact certificate/key elements. Returns True if this is a cert/key element."""
        if not self._is_cert_tag(tag, tag_base):
            return False

        if self._looks_like_cert_material(element.text):
            self._redact_text_and_track(element, 'Cert/Key', '[REDACTED_CERT_OR_KEY]')
            return True

        # Short, no PEM header: either a reference the config defines, or a
        # secret sitting in a cert-named element. Redacted as a secret rather
        # than as cert material, because by this point it demonstrably is not
        # cert material.
        if self._holds_unresolvable_cert_reference(tag, tag_base, element):
            self._redact_text_and_track(element, 'Secret')

        return True

    def _redact_ip_containing_element(self, tag: str, tag_base: str, element: ET.Element) -> bool:
        """Redact IPs/domains in known IP-containing elements. Returns True if processed."""
        if (tag in self.ip_containing_elements or tag_base in self.ip_containing_elements):
            if element.text:
                element.text = self.redact_text(element.text, self.redact_ips, self.redact_domains)
                return True
        return False

    @staticmethod
    def _is_secret_name(name: str) -> bool:
        """Whether a name denotes a secret, deny-list applied

        The single classification used for element names, attribute names and
        key names inside blob text, so the same word cannot mean different
        things in the three places it can appear.
        """
        lowered = name.lower()
        if lowered in SECRET_TAG_DENYLIST:
            return False
        return bool(SECRET_NAME_PATTERN.search(lowered))

    def _should_redact_attribute(self, attr: str) -> bool:
        """Whether an attribute's value should be removed on the strength of its name

        Two reasons: the name denotes a secret, or the name denotes free prose
        and --redact-descriptions was asked for. The second is opt-in because
        notes and labels are often the most useful part of a config to a reader.

        The deny-list applies here as it does to element names. 'keylen' and
        'certref' name a length and a reference wherever they appear.
        """
        if self._is_secret_name(attr):
            return True
        if not self.redact_descriptions:
            return False
        return attr.lower() in DESCRIPTION_ATTRIBUTES

    def _replace_attribute(self, element: ET.Element, attr: str, category: str = 'Secret',
                           placeholder: str = '[REDACTED]') -> None:
        """Swap an attribute's value for a placeholder and count it"""
        original = element.attrib[attr]
        element.attrib[attr] = placeholder

        if category == 'Cert/Key':
            self.stats['certs_redacted'] += 1
        else:
            self.stats['secrets_redacted'] += 1

        self._add_sample(category, original, placeholder)

    def _account_for_attribute_blob(self, element: ET.Element, tag: str, attr: str) -> None:
        """Redact or report key material in an attribute whose name says nothing

        Reported rather than redacted by default. No pfSense config examined in
        testing uses XML attributes at all, so this guards against third-party
        packages rather than an observed leak, and rewriting values on that
        basis would over-redact for everyone. Reporting costs nothing and is
        what the element path has always done.

        Private-key material and JWTs are the exceptions, on the same reasoning
        as _redact_unknown_blob_element: they are removed here rather than
        reported, in every mode. Both paths classify through
        unambiguous_secret_kind, so the two cannot decide the same value
        differently.
        """
        value = element.attrib[attr]

        if self._redact_unambiguous_secret_attribute(element, attr, value):
            return

        # As in _account_for_opaque_element: the unambiguous cases are already
        # ruled out above, so the complete predicate would decode twice.
        if not self._is_opaque_value(value):
            return

        if self.aggressive:
            self._replace_attribute(element, attr, 'Cert/Key', '[REDACTED_CERT_OR_KEY]')
            return

        self._record_retained_path(f"{'/'.join([*self._path_stack, tag])}[@{attr}]")

    def _redact_unambiguous_secret_attribute(
        self, element: ET.Element, attr: str, value: str
    ) -> bool:
        """The attribute counterpart of _redact_unambiguous_secret_element

        Same classification, same ordering, same placeholders - only the
        mechanism for replacing the value differs.
        """
        kind = unambiguous_secret_kind(value)
        if kind is None:
            return False

        category, placeholder = _redaction_for(kind)
        self._replace_attribute(element, attr, category, placeholder)
        return True

    def _redact_sensitive_attributes(self, element: ET.Element, tag: str) -> None:
        """Handle attribute values: redact by name, and account for blobs in the rest

        SENSITIVE_ATTR_PATTERN only ever sees an attribute's *name*. A value
        that is plainly key material, sitting in an attribute named something
        unremarkable, used to be invisible to the redactor and to --fail-on-warn
        alike - so a CI gate passed on a file whose own output never mentioned
        it. Elements have been handled this way since _redact_unknown_blob_element;
        this gives attributes the same treatment.
        """
        for attr in list(element.attrib.keys()):
            if self._should_redact_attribute(attr):
                self._replace_attribute(element, attr)
                continue
            self._account_for_attribute_blob(element, tag, attr)

    def _redact_text_aggressive(self, element: ET.Element, text_already_processed: bool) -> None:
        """Redact text and attributes in aggressive mode"""
        tag = self._normalise_tag(element.tag)
        if self._is_secret_tag(tag, self._get_tag_base(tag)):
            return

        # Process text if not already done
        if element.text and not text_already_processed:
            element.text = self.redact_text(element.text, self.redact_ips, self.redact_domains)

        # Process tail
        if element.tail:
            element.tail = self.redact_text(element.tail, self.redact_ips, self.redact_domains)

        # Process attributes
        for attr in list(element.attrib.keys()):
            if element.attrib[attr]:
                element.attrib[attr] = self.redact_text(
                    element.attrib[attr], self.redact_ips, self.redact_domains
                )

    @staticmethod
    def _carries_unhandled_url(text: str | None, handled: bool) -> bool:
        """Whether text still needs the URL-credential pass

        'handled' means an earlier, more specific pass already rewrote this
        element, so running the URL pass over it again would double-process it.
        """
        return bool(text) and not handled and '://' in text

    def _redact_element_text(self, tag: str, tag_base: str, element: ET.Element) -> bool:
        """Run the text-content passes. Returns whether the text was handled

        The return value gates the later passes, so a pass that fully rewrote
        the text stops a subsequent one from processing it again. Order matters:
        the URL pass runs last and only on text nothing else claimed.
        """
        # Opaque free-text containers (custom_options, upsd_users, ...) that
        # carry credentials inline rather than in dedicated elements
        handled = self._redact_blob_text_element(tag, tag_base, element)

        # Descriptions/identifiers - opt-in via --redact-descriptions
        if self._redact_description_element(tag, tag_base, element):
            handled = True

        # Unrecognised high-entropy leaf values (third-party package fields)
        if self._redact_unknown_blob_element(tag, element):
            handled = True

        if self._redact_ip_containing_element(tag, tag_base, element):
            handled = True

        # Credentials embedded in URLs in elements that are not known URL
        # carriers (e.g. <updateurl>, <webhook_url>). Previously these were
        # only touched under --aggressive, so the token survived by default.
        # Host anonymisation deliberately stays out of the default path here.
        if self._carries_unhandled_url(element.text, handled):
            element.text = self._redact_url_secrets_only(element.text)

        return handled

    def redact_element(self, element: ET.Element) -> None:
        """Recursively redact sensitive information from XML element"""

        # Normalise tag name to handle namespaced exports
        tag = self._normalise_tag(element.tag)

        # Strip trailing digits from tag to handle numbered variants (e.g., dnsserver6 -> dnsserver)
        tag_base = self._get_tag_base(tag)

        # <key> is handled specially (PEM blob vs short secret) and must be
        # checked before the generic secret match, which would otherwise claim
        # it via SECRET_TAG_PATTERN and lose the cert/key distinction.
        if self._redact_key_element_if_needed(tag, element):
            return

        # Handle complete redaction cases
        if self._should_redact_completely(tag, tag_base, element):
            return

        # Handle cert/key elements (don't return - continue to process children)
        self._redact_cert_key_element(tag, tag_base, element)

        text_already_processed = self._redact_element_text(tag, tag_base, element)

        # Redact attributes with sensitive names, and account for high-entropy
        # values in the rest. Runs before the aggressive text pass below, which
        # would otherwise rewrite the values this needs to see.
        self._redact_sensitive_attributes(element, tag)

        # Recursively process child elements
        self._path_stack.append(tag)
        try:
            for child in element:
                self.redact_element(child)
        finally:
            self._path_stack.pop()

        # Aggressive mode: apply redaction to text content, tail, and attributes
        if self.aggressive:
            self._redact_text_aggressive(element, text_already_processed)

    def _add_redaction_comment(self, root: ET.Element) -> None:
        """Add a comment to the XML indicating it was redacted"""
        comment_text = f" Redacted using pfsense-redactor v{resolve_version()} "
        comment = ET.Comment(comment_text)

        # Insert comment as first child of root
        root.insert(0, comment)

    def _check_root_tag(self, root: ET.Element) -> bool:
        """Warn if this does not look like a pfSense config. False means abort

        Namespace-robust. Only --fail-on-warn turns the warning into an abort.
        """
        if root.tag.rsplit('}', 1)[-1].lower() == 'pfsense':
            return True

        msg = f"[!] Warning: Root tag is '{root.tag}', expected 'pfsense'."
        if self.fail_on_warn:
            self.logger.error("%s Exiting.", msg)
            return False

        self.logger.warning("%s Proceeding anyway...", msg)
        return True

    def _load_config_tree(self, input_file: str) -> ET.ElementTree | None:
        """Parse the configuration, refusing input pfSense would not produce

        None means abort; the reason has already been logged. Both checks live
        here so that redact_config has one failure branch rather than three.
        """
        refusal = _prolog_refusal_reason(input_file)
        if refusal is not None:
            self.logger.error(
                "[!] Refusing to parse this file because %s. Entity expansion "
                "in a DOCTYPE can turn a small file into gigabytes of memory, "
                "so the prolog is checked before parsing.", refusal
            )
            return None

        # Scanners flag any stdlib xml use as XXE-prone. It does not apply:
        # ElementTree does not resolve external entities (a SYSTEM entity
        # raises ParseError, so no file disclosure and no SSRF), and the
        # prolog refusal above is stricter still, blocking internal entity
        # expansion too. defusedxml would add a runtime dependency, which
        # tests/integration/test_standalone_script.py exists to prevent.
        #
        # The suppression sits on the statement itself: it applies to its own
        # line or the one directly below, so it cannot be parked above a
        # comment block like this one.
        tree = ET.parse(input_file)  # nosemgrep  # nosec
        if not self._check_root_tag(tree.getroot()):
            return None

        return tree

    @staticmethod
    def serialise_tree(tree: ET.ElementTree) -> str:
        """Serialise a tree to exactly the text _write_output would produce

        Byte-for-byte identity with the written file is the point: verifying
        anything else - the tree, the statistics, a summary - verifies
        something other than what the operator ends up sharing. Pinned by
        tests/unit/test_output_verification.py.
        """
        return ET.tostring(
            tree.getroot(), encoding='utf-8', xml_declaration=True
        ).decode('utf-8')

    def _allowlisted_literals(self) -> frozenset[str]:
        """Values the operator explicitly asked to keep, lower-cased

        Passed to the verifier so that an allow-listed domain or address
        surviving verbatim is not reported as a retained value. Nothing else is
        excluded on the operator's say-so.
        """
        literals = {str(addr).lower() for addr in self.allowlist_ip_addrs}
        literals.update(domain.lower() for domain in self.allowlist_domains)
        literals.update(domain.lower() for domain in self.allowlist_domains_idna)
        return frozenset(literals)

    def _snapshot_input_values(self, root: ET.Element) -> None:
        """Record the input's leaf and attribute values before redaction

        Redaction rewrites the tree in place, so the retention comparison has
        to take its copy first. Values only - not the tree - because the list is
        bounded and a second copy of the document is not.
        """
        if VERIFIER is None:
            self._input_values = []
            return
        self._input_values = VERIFIER.collect_input_values(
            root, self._allowlisted_literals()
        )

    def verify_candidate_output(self, candidate: str):
        """Independently verify serialised candidate output

        Returns a VerificationResult, or None when verifier.py could not be
        imported. **None is not a pass.** Callers must distinguish "verified
        clean" from "not verified", because conflating them is the fail-open
        behaviour this whole module exists to remove.

        Advisory in 1.2.2: the result is reported and does not decide whether
        output is written. Enforcement arrives with the verify-before-write
        change.
        """
        if VERIFIER is None:
            return None

        findings = list(VERIFIER.scan_shapes(candidate).findings)
        findings.extend(VERIFIER.scan_retention(self._input_values, candidate).findings)
        return VERIFIER.build_result(findings)

    def _report_verification(self, result) -> None:
        """Report an advisory verification result on stderr

        describe() builds its lines from finding metadata only, so this cannot
        print a secret by printing a finding.
        """
        if result is None:
            self.logger.warning(
                "[!] Independent verification unavailable: verifier.py is not "
                "importable. Redaction ran, but nothing re-read the output."
            )
            return

        if result.clean:
            self.logger.info("[+] Independent verification: no findings")
            return

        self.logger.warning("")
        self.logger.warning(
            "[!] Independent verification found %d issue(s) in the output:",
            result.count
        )
        for line in VERIFIER.describe(result):
            self.logger.warning("    - %s", line)

    def _write_output(
        self, tree: ET.ElementTree, input_file: str, output_file: str | None,
        stdout_mode: bool, inplace: bool
    ) -> None:
        """Write the redacted tree to stdout, over the input, or to a new file"""
        if stdout_mode:
            tree.write(sys.stdout.buffer, encoding='utf-8', xml_declaration=True)
            return

        if inplace:
            tree.write(input_file, encoding='utf-8', xml_declaration=True)
            self.logger.info("[+] Redacted configuration written in-place to: %s", input_file)
            return

        tree.write(output_file, encoding='utf-8', xml_declaration=True)
        self.logger.info("[+] Redacted configuration written to: %s", output_file)

    def redact_config(
        self,
        input_file: str,
        output_file: str | None,
        redact_ips: bool = True,
        redact_domains: bool = True,
        dry_run: bool = False,
        stdout_mode: bool = False,
        inplace: bool = False
    ) -> bool:
        """Redact pfSense configuration file"""
        try:
            tree = self._load_config_tree(input_file)
            if tree is None:
                return False
            root = tree.getroot()

            # Both lines are progress reporting under the same condition, and
            # nothing runs between them, so they share one guard.
            if not dry_run and not stdout_mode:
                self.logger.info("[+] Parsing XML configuration from: %s", input_file)
                self.logger.info("[+] Redacting sensitive information...")

            # Policy for this run, set before the traversal reads it. Assigned
            # on every call so a reused instance cannot inherit the previous
            # run's flags.
            self.redact_ips = redact_ips
            self.redact_domains = redact_domains

            # Before the traversal, so certificate references can be resolved
            # against what the config actually defines
            self.known_refids = self._collect_refids(root)

            # Also before the traversal: the retention comparison needs the
            # input's values, and redaction overwrites them in place.
            self._snapshot_input_values(root)

            self.redact_element(root)

            # Dry run mode: just print stats
            if dry_run:
                self.logger.info("[+] Dry run - no files modified")
                self._print_stats()
                return self._retained_values_are_acceptable()

            # Add redaction comment to the root element
            self._add_redaction_comment(root)

            # Pretty print (Python 3.9+)
            ET.indent(tree, space="  ")

            # Advisory in this release: reported, not enforced. The candidate
            # is serialised once and both verified and written from the same
            # text, so what is checked is what is shared.
            self.last_verification = self.verify_candidate_output(
                self.serialise_tree(tree)
            )

            self._write_output(tree, input_file, output_file, stdout_mode, inplace)

            # Print summary (always print, logger routes to correct stream)
            self._print_stats()
            self._report_verification(self.last_verification)

            return self._retained_values_are_acceptable()

        except ET.ParseError as e:
            self.logger.error("[!] Error parsing XML: %s", e)
            return False
        except (IOError, OSError) as e:
            self.logger.error("[!] Error reading/writing file: %s", e)
            return False
        except (ValueError, TypeError) as e:
            self.logger.error("[!] Error processing configuration: %s", e)
            return False

    def _retained_values_are_acceptable(self) -> bool:
        """Whether the run should be treated as successful

        False only under --fail-on-warn, and only when high-entropy values were
        left in place. The warning naming them has already been printed.

        Without this the flag covered the root-tag check alone, so a CI job
        could pass on a file the tool had just told the operator to review
        before sharing. A gate that cannot fail is not a gate.
        """
        if not self.fail_on_warn:
            return True
        if not self.stats['high_entropy_retained']:
            return True

        self.logger.error(
            "[!] Failing because --fail-on-warn is set and %d high-entropy "
            "value(s) were retained. Re-run with --aggressive to redact them, "
            "or review the paths listed above.",
            self.stats['high_entropy_retained']
        )
        return False

    def _print_stats(self) -> None:
        """Print redaction statistics using logger"""
        self.logger.info("")
        self.logger.info("[+] Redaction summary:")
        for key, label in STAT_LABELS:
            if self.stats[key]:
                self.logger.info("    - %s: %d", label, self.stats[key])

        self._print_retained_warning()
        self._print_anonymisation_stats()
        self._print_samples()

    def _print_retained_warning(self) -> None:
        """Report high-entropy values that were deliberately not redacted

        The summary otherwise only reports what was redacted, which makes
        retained secrets impossible to audit before sharing.
        """
        if not self.stats['high_entropy_retained']:
            return

        self.logger.warning("")
        self.logger.warning(
            "[!] %d unrecognised high-entropy value(s) retained. Review before sharing:",
            self.stats['high_entropy_retained']
        )
        for path in self.high_entropy_paths[:self.RETAINED_PATHS_SHOWN]:
            self.logger.warning("    - %s", path)
        if len(self.high_entropy_paths) > self.RETAINED_PATHS_SHOWN:
            self.logger.warning(
                "    - ... and %d more",
                len(self.high_entropy_paths) - self.RETAINED_PATHS_SHOWN
            )
        self.logger.warning("    Re-run with --aggressive to redact these automatically.")

    def _print_anonymisation_stats(self) -> None:
        """Report how many unique identifiers were aliased"""
        if not self.anonymise:
            return

        self.logger.info("")
        self.logger.info("[+] Anonymisation stats:")
        self.logger.info("    - Unique IPs anonymised: %d", len(self.ip_aliases))
        self.logger.info("    - Unique domains anonymised: %d", len(self.domain_aliases))

    def _print_samples(self) -> None:
        """Print masked before/after examples for --dry-run-verbose"""
        if not self.dry_run_verbose:
            return

        self.logger.info("")
        self.logger.info("[+] Samples of changes (limit N=%d):", self.sample_limit)

        printed = False
        for category in SAMPLE_CATEGORIES:
            for before_masked, after in self.samples.get(category) or ():
                self.logger.info("    %s: %s -> %s", category, before_masked, after)
                printed = True

        if not printed:
            self.logger.info("    (no examples collected)")


# ==========================================================================
# 6. ALLOWLISTS
# ==========================================================================
def parse_allowlist_file(filepath: str, silent_if_missing: bool = False) -> tuple[set[str], list[IPNetwork], set[str]]:
    """Parse allow-list file containing IPs, CIDR networks, and domains (one per line)

    Format:
    - One item per line
    - Blank lines ignored
    - Lines starting with # are comments (ignored)
    - Items can be IPs, CIDR networks, or domains

    Args:
        filepath: Path to allow-list file
        silent_if_missing: If True, return empty sets if file doesn't exist (for default files)

    Returns:
        tuple: (set of IP strings, list of IP network objects, set of domains)
    """
    ips: set[str] = set()
    networks: list[IPNetwork] = []
    domains: set[str] = set()

    try:
        with open(filepath, 'r', encoding='utf-8') as file_handle:
            for raw_line in file_handle:
                _classify_allowlist_entry(raw_line.strip(), ips, networks, domains)

    except FileNotFoundError:
        if silent_if_missing:
            # Default allow-list files are optional
            return set(), [], set()
        _exit_allowlist_error("[!] Error: Allow-list file '%s' not found", filepath)
    except (IOError, OSError) as e:
        _exit_allowlist_error("[!] Error reading allow-list file: %s", e)
    except (ValueError, UnicodeDecodeError) as e:
        _exit_allowlist_error("[!] Error parsing allow-list file: %s", e)

    return ips, networks, domains


def _classify_allowlist_entry(
    line: str, ips: set[str], networks: list[IPNetwork], domains: set[str]
) -> None:
    """Sort one stripped allow-list line into IPs, networks or domains

    Blank lines and whole-line comments are ignored. Anything that parses as
    neither an address nor a network is treated as a domain, which is why a
    malformed entry silently becomes a domain rather than an error.
    """
    if not line or line.startswith('#'):
        return

    try:
        ipaddress.ip_address(line)
        ips.add(line)
        return
    except ValueError:
        pass

    try:
        # strict=False so 10.1.2.3/8 is accepted and normalised
        networks.append(ipaddress.ip_network(line, strict=False))
        return
    except ValueError:
        pass

    # Domain matching is case-insensitive
    domains.add(line.lower())


def _exit_allowlist_error(message: str, detail: object) -> NoReturn:
    """Report an allow-list failure and exit non-zero"""
    logging.getLogger('pfsense_redactor').error(message, detail)
    sys.exit(1)


def find_default_allowlist_files() -> list[Path]:
    """Find default allow-list files in standard locations

    Checks in order:
    1. .pfsense-allowlist in current directory
    2. ~/.pfsense-allowlist in home directory

    Returns:
        list: Paths to existing default allow-list files
    """
    default_files = []

    # Check current directory
    local_file = Path('.pfsense-allowlist')
    if local_file.exists():
        default_files.append(local_file)

    # Check home directory
    home_file = Path.home() / '.pfsense-allowlist'
    if home_file.exists():
        default_files.append(home_file)

    return default_files

# ==========================================================================
# 7. PATH SAFETY
# ==========================================================================
def _windows_dirs_from_environment() -> set[str]:
    """Locate the real Windows system directories from the environment

    The hardcoded list assumes C:. Windows can be installed on any drive, and
    ProgramFiles/ProgramData are relocatable independently of it, so a machine
    with the system on D: had no protection for D:\\Windows at all.

    Returns an empty set off Windows, where none of these variables are set.
    """
    dirs: set[str] = set()

    for variable in ('SystemRoot', 'windir', 'ProgramFiles', 'ProgramFiles(x86)',
                     'ProgramW6432', 'ProgramData'):
        value = os.environ.get(variable)
        if not value:
            continue

        dirs.add(value.lower())

        # System32 sits under SystemRoot and is worth naming explicitly, since
        # the most damaging writes land there rather than in the root.
        #
        # Joined with a literal backslash rather than os.path.join: these are
        # Windows paths, and join would use the *host* separator, producing
        # 'd:\\windows/system32' when the set is built on POSIX - as it is in
        # the tests that simulate a Windows environment.
        if variable in ('SystemRoot', 'windir'):
            dirs.add((value.rstrip('/\\') + '\\system32').lower())

    return dirs


def _get_sensitive_directories() -> frozenset[str]:
    """Get list of sensitive system directories that should not be written to

    Returns:
        frozenset: Set of sensitive directory paths (normalised)
    """
    # Unix/Linux/macOS sensitive directories
    unix_sensitive_dirs = {
        '/etc', '/sys', '/proc', '/dev', '/boot', '/root',
        '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/lib', '/lib64',
        '/var/log', '/var/run', '/run',
    }

    # Windows system directories. The literals assume the system is on C:,
    # which is usual but not guaranteed - Windows can be installed on any
    # drive. They are kept because the whole set is applied on every platform
    # (see below), and supplemented with the real locations read from the
    # environment, the same way _is_safe_absolute_location reads TMPDIR/TEMP.
    windows_sensitive_dirs = {
        'c:\\windows', 'c:\\windows\\system32', 'c:\\program files',
        'c:\\program files (x86)', 'c:\\programdata',
    }
    windows_sensitive_dirs |= _windows_dirs_from_environment()

    # Normalise paths for comparison (resolve symlinks, make absolute)
    normalised = set()

    # Always include all sensitive directories (cross-platform security)
    # This ensures Unix paths are blocked on Windows and vice versa
    all_sensitive = unix_sensitive_dirs | windows_sensitive_dirs

    for path_str in all_sensitive:
        try:
            path = Path(path_str)
            # Only try to resolve if the path exists on this platform
            # This prevents errors when checking Unix paths on Windows
            if path.exists():
                normalised.add(str(path.resolve()).lower())
            else:
                # Add as-is for non-existent paths (still useful for pattern matching)
                # This is critical for cross-platform security
                normalised.add(path_str.lower())
        except (OSError, RuntimeError):
            # Handle errors in path resolution (e.g., permission denied)
            normalised.add(path_str.lower())

    # Canonicalise: no entry carries a trailing separator, so the set is
    # predictable for callers and comparisons do not depend on how an entry
    # was spelled. _is_in_sensitive_directory strips defensively as well,
    # because it also accepts hand-built sets.
    return frozenset(entry.rstrip('/\\') or entry for entry in normalised)


# System files that must never be written to, compared against the resolved
# lower-cased path. Checked in addition to the sensitive-directory scan.
DANGEROUS_OUTPUT_FILES: frozenset[str] = frozenset({
    '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
    '/etc/hosts', '/etc/fstab', '/etc/crontab',
    'c:\\windows\\system32\\config\\sam',
    'c:\\windows\\system32\\config\\system',
})


def _resolve_for_validation(file_path: str, path: Path) -> tuple[Path, bool]:
    """Resolve a path to absolute form. Returns (resolved, was_absolute)

    Windows drive-letter paths are detected explicitly because Path.is_absolute
    returns False for them on POSIX, which would otherwise let 'C:\\...' be
    treated as relative and resolved against the working directory.
    """
    is_windows_absolute = (
        len(file_path) >= 3 and
        file_path[1:3] in (':\\', ':/')  # C:\ or C:/
    )
    is_absolute_form = path.is_absolute() or is_windows_absolute

    # Follows symlinks; relative paths resolve against the working directory
    resolved = path.resolve() if is_absolute_form else (Path.cwd() / path).resolve()
    return resolved, is_absolute_form


def _is_in_sensitive_directory(resolved_str: str, sensitive_dirs: frozenset[str]) -> bool:
    """Check whether a resolved output path falls inside a protected directory

    Matching is component-aware: '/root' must not match '/rootkit', and
    '/var/log' must not match '/var/logs-archive'. A bare startswith rejected
    both of those legitimate paths.

    Compared as strings rather than via Path.is_relative_to because
    sensitive_dirs deliberately holds both POSIX and Windows entries, and the
    Windows ones are not parseable as paths on POSIX.
    """
    for sensitive_dir in sensitive_dirs:
        try:
            # Strip any trailing separator first, so the comparisons do not
            # depend on how the entry was written. Path.resolve() never returns
            # a trailing separator, so an entry of '/etc/' would otherwise fail
            # to match a resolved path of exactly '/etc'.
            base = sensitive_dir.rstrip('/\\')

            if resolved_str == base:
                return True

            # Require a separator after the prefix so only whole path
            # components match. Both separators are checked because the
            # sensitive list spans platforms.
            if any(resolved_str.startswith(base + sep) for sep in ('/', '\\')):
                return True
        except (ValueError, AttributeError):
            pass
    return False


def _is_safe_absolute_location(resolved_str: str) -> bool:
    """Check whether an absolute path points somewhere writing is acceptable

    Safe means the current working directory, the user's home, or a system
    temp directory. Called only when --allow-absolute-paths was not given, and
    only after the sensitive-directory check has already run.
    """
    # Normalise to forward slashes so Windows and POSIX compare alike
    resolved_normalised = resolved_str.replace('\\', '/')

    safe_prefixes = [
        str(Path.home()).lower(),
        str(Path.cwd()).lower(),
        str(Path(os.environ.get('TMPDIR', '/tmp'))).lower(),
        str(Path(os.environ.get('TEMP', '/tmp'))).lower(),
        str(Path(os.environ.get('TMP', '/tmp'))).lower(),
        '/tmp',  # Standard Unix temp directory
        '/private/tmp',  # macOS /tmp (canonical path)
        '/var/folders',  # macOS temp
        '/private/var/folders',  # macOS temp (canonical)
    ]

    # The cwd itself is safe, as well as anything beneath it
    cwd_normalised = str(Path.cwd()).lower().replace('\\', '/')
    if not cwd_normalised.endswith('/'):
        cwd_normalised += '/'
    if resolved_normalised.startswith(cwd_normalised) or resolved_normalised == cwd_normalised.rstrip('/'):
        return True

    # Require the separator so /tmpfoo does not match the /tmp prefix
    return any(
        resolved_normalised.startswith(prefix if prefix.endswith('/') else prefix + '/')
        for prefix in (p.replace('\\', '/') for p in safe_prefixes)
    )


def validate_file_path(
    file_path: str,
    allow_absolute: bool = False,
    is_output: bool = False,
    sensitive_dirs: frozenset[str] | None = None
) -> tuple[bool, str, Path | None]:
    """Validate file path for security issues

    Checks for:
    - Absolute paths to system directories (unless allow_absolute=True)
    - Directory traversal attempts (../)
    - Paths resolving to sensitive system directories
    - Null bytes in path

    Args:
        file_path: Path to validate
        allow_absolute: If True, allow absolute paths (default: False)
        is_output: If True, this is an output path (stricter checks)
        sensitive_dirs: Set of sensitive directories (computed if None)

    Returns:
        tuple: (is_valid, error_message, resolved_path)
               If valid: (True, "", resolved_path)
               If invalid: (False, error_message, None)
    """
    if sensitive_dirs is None:
        sensitive_dirs = _get_sensitive_directories()

    # Check for null bytes (path traversal attack vector)
    if '\0' in file_path:
        return False, "Path contains null bytes", None

    try:
        path = Path(file_path)

        # Check for directory traversal in the raw path string
        # This catches attempts like "../../../etc/passwd" before resolution
        if '..' in path.parts:
            return False, "Path contains directory traversal components (..)", None

        resolved, is_absolute_form = _resolve_for_validation(file_path, path)

        # ORDER IS SECURITY-CRITICAL and is asserted by _resolved_path_error:
        # the sensitive-directory check must run before the absolute-path check,
        # so --allow-absolute-paths cannot be used to write into a protected
        # directory.
        error = _resolved_path_error(
            file_path, resolved, is_absolute_form, allow_absolute, is_output, sensitive_dirs
        )
        if error:
            return False, error, None

        return True, "", resolved

    except (OSError, RuntimeError, ValueError) as e:
        return False, f"Error validating path: {e}", None


def _is_disallowed_absolute(is_absolute_form: bool, allow_absolute: bool,
                            resolved_str: str) -> bool:
    """Whether an absolute path is refused for being absolute

    Only the reason is named here, not the ordering: this check must still run
    *after* the sensitive-directory check in _resolved_path_error, so that
    --allow-absolute-paths cannot reach a protected directory.
    """
    return (is_absolute_form
            and not allow_absolute
            and not _is_safe_absolute_location(resolved_str))


def _resolved_path_error(
    file_path: str, resolved: Path, is_absolute_form: bool, allow_absolute: bool,
    is_output: bool, sensitive_dirs: frozenset[str]
) -> str | None:
    """Return the first failure among the resolved-path checks, else None

    Checks run in this order deliberately:
    1. sensitive directory - must precede the absolute check so that
       --allow-absolute-paths still cannot reach a protected directory
    2. absolute path outside the safe locations
    3. specific system configuration files
    """
    resolved_str = str(resolved).lower()

    if is_output and _is_in_sensitive_directory(resolved_str, sensitive_dirs):
        return f"Cannot write to sensitive system directory: {resolved}"

    if _is_disallowed_absolute(is_absolute_form, allow_absolute, resolved_str):
        return f"Absolute paths not allowed (use --allow-absolute-paths): {file_path}"

    if is_output and resolved_str in DANGEROUS_OUTPUT_FILES:
        return f"Cannot write to system configuration file: {resolved}"

    return None




# ==========================================================================
# 8. CLI
# ==========================================================================
def _build_arg_parser(version: str) -> argparse.ArgumentParser:
    """Construct the CLI parser

    Split into groups by _add_*_arguments helpers: 25 add_argument calls in
    one function exceeded the 50-line method limit Codacy enforces.
    """
    parser = argparse.ArgumentParser(
        description='Redact sensitive information from pfSense XML configuration files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s config.xml config-redacted.xml
  %(prog)s config.xml config-redacted.xml --no-redact-ips
  %(prog)s config.xml config-redacted.xml --keep-private-ips
  %(prog)s config.xml config-redacted.xml --anonymise
  %(prog)s config.xml --inplace --force
  %(prog)s config.xml --stdout > config-redacted.xml
  %(prog)s config.xml config-redacted.xml --dry-run
  %(prog)s config.xml config-redacted.xml --aggressive
  %(prog)s config.xml config-redacted.xml --allowlist-ip 8.8.8.8 --allowlist-domain time.nist.gov
  %(prog)s config.xml config-redacted.xml --allowlist-file allowlist.txt

Allow-list file format (one item per line):
  # Public DNS servers
  8.8.8.8
  1.1.1.1
  # NTP servers
  time.nist.gov
  pool.ntp.org

IMPORTANT: Redacted output is intended for sharing/review only.
Do not restore redacted configs to pfSense as XML comments and
CDATA sections are not preserved.
        """
    )

    parser.add_argument('--version', action='version', version=f'%(prog)s {version}',
                        help='Show program version and exit')
    parser.add_argument('--check-version', action='store_true',
                        help='Check for updates from PyPI')

    _add_io_arguments(parser)
    _add_redaction_arguments(parser)
    _add_output_arguments(parser)
    _add_allowlist_arguments(parser)
    return parser


def _add_io_arguments(parser: argparse.ArgumentParser) -> None:
    """Positional input/output paths"""
    parser.add_argument('input', nargs='?', help='Input pfSense config.xml file (required unless --check-version is used)')
    parser.add_argument('output', nargs='?', help='Output redacted config.xml file')

def _add_redaction_arguments(parser: argparse.ArgumentParser) -> None:
    """Flags controlling what gets redacted and how"""
    parser.add_argument('--no-redact-ips', action='store_true',
                        help='Do not redact IP addresses')
    parser.add_argument('--no-redact-domains', action='store_true',
                        help='Do not redact domain names')
    parser.add_argument('--keep-private-ips', dest='keep_private_ips', action='store_true', default=None,
                        help='Keep non-global IP addresses visible (RFC1918/ULA/loopback/link-local/multicast/reserved/unspecified). Note: Common netmasks (255.x.x.x) and unspecified addresses (0.0.0.0, ::) are always preserved for readability.')
    parser.add_argument('--no-keep-private-ips', dest='keep_private_ips', action='store_false',
                        help='When used with --anonymise, do NOT keep private IPs visible.')
    parser.add_argument('--anonymise', action='store_true',
                        help='Use consistent aliases (IP_1, domain1.example) to preserve topology. Implies --keep-private-ips unless --no-keep-private-ips is specified')

def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    """Flags controlling where output goes and how noisy the run is"""
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be redacted without writing output')
    parser.add_argument('--stdout', action='store_true',
                        help='Write redacted XML to stdout')
    parser.add_argument('--inplace', action='store_true',
                        help='Overwrite input file with redacted output')
    parser.add_argument('--force', action='store_true',
                        help='Overwrite output file if it exists')
    parser.add_argument('--aggressive', action='store_true',
                        help='Apply IP/domain redaction to all element text, not just known fields')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress progress messages (show only warnings and errors)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed debug information')
    parser.add_argument('--fail-on-warn', action='store_true',
                        help='Exit with non-zero code if root tag is not pfsense (useful in CI)')

def _add_allowlist_arguments(parser: argparse.ArgumentParser) -> None:
    """Allow-list sources and the remaining opt-in redaction flags"""
    parser.add_argument('--allowlist-ip', action='append', dest='allowlist_ips', metavar='IP_OR_CIDR',
                        help='IP or CIDR to never redact (repeatable). Applies to both raw text and URLs.')
    parser.add_argument('--allowlist-domain', action='append', dest='allowlist_domains', metavar='DOMAIN',
                        help='Domain to never redact (repeatable). Supports suffix matching (e.g., example.org preserves sub.example.org) and IDNA/punycode. Applies to bare FQDNs and URL hostnames. Case-insensitive.')
    parser.add_argument('--allowlist-file', metavar='PATH',
                        help='File containing IPs, CIDR networks, and domains to never redact (one per line). Blank lines and lines starting with # are ignored. Items are merged with --allowlist-ip and --allowlist-domain flags.')
    parser.add_argument('--no-default-allowlist', action='store_true',
                        help='Do not load default allow-list files (.pfsense-allowlist in current directory or ~/.pfsense-allowlist)')
    parser.add_argument('--dry-run-verbose', action='store_true',
                        help='Like --dry-run, but also show examples of what would be redacted')
    parser.add_argument('--redact-url-usernames', action='store_true',
                        help='Redact usernames in URLs (e.g., ftp://user@host becomes ftp://REDACTED@host). By default, usernames are preserved whilst passwords are always redacted.')
    parser.add_argument('--redact-descriptions', action='store_true',
                        help='Redact free-text descriptions and identifiers (descr, detail, hostname, ssid). These often contain personal names, e.g. DHCP static-map descriptions. Off by default as they aid troubleshooting.')
    parser.add_argument('--allow-absolute-paths', action='store_true',
                        help='Allow absolute file paths (e.g., /etc/passwd, C:\\config.xml). By default, only relative paths are permitted for security. Use with caution.')



def _resolve_input_path(
    args: argparse.Namespace, sensitive_dirs: frozenset[str], logger: logging.Logger
) -> None:
    """Validate the input path and its file. Exits non-zero on any failure

    Sets args.input to the resolved path, as the inline version did.
    """
    # Validate input file path
    input_valid, input_error, input_resolved = validate_file_path(
        args.input,
        allow_absolute=args.allow_absolute_paths,
        is_output=False,
        sensitive_dirs=sensitive_dirs
    )
    if not input_valid:
        logger.error("[!] Error: Invalid input path: %s", input_error)
        sys.exit(1)

    # Check if input file exists (use resolved path)
    if not input_resolved.exists():
        logger.error("[!] Error: Input file '%s' not found", args.input)
        sys.exit(1)

    # SECURITY: Check if input is a symlink when using --inplace
    # Must check BEFORE file size check (directories appear empty when read as files)
    if args.inplace:
        input_path_original = Path(args.input)
        if input_path_original.is_symlink():
            # Get the symlink target for the error message
            try:
                target = input_path_original.resolve()
                logger.error("[!] Error: Cannot use --inplace on symlink: %s", args.input)
                logger.error("    Symlink target: %s", target)
                logger.error("    Hint: If you intend to modify the target, specify it directly.")
            except (OSError, RuntimeError):
                # If we can't resolve the symlink (broken link), still refuse
                logger.error("[!] Error: Cannot use --inplace on symlink: %s", args.input)
                logger.error("    Hint: Symlinks are not allowed with --inplace for security reasons.")
            sys.exit(1)

    # Check if input file is empty
    if input_resolved.stat().st_size == 0:
        logger.error("[!] Error: Input file is empty")
        sys.exit(1)


def _output_path_will_be_used(args: argparse.Namespace) -> bool:
    """Whether args.output is worth validating

    The only skipped case is --stdout without --dry-run, where args.output is
    never written.
    """
    return bool(args.output) and (args.dry_run or not args.stdout)


def _would_overwrite_without_force(args: argparse.Namespace, resolved: Path) -> bool:
    """Whether writing would destroy an existing file the user did not consent to

    Overwrite protection applies only when a write will actually happen, so the
    modes that write nothing are excluded first, then explicit consent.
    """
    if args.dry_run or args.stdout:
        return False
    if args.force:
        return False
    return resolved.exists()


def _resolve_output_path(
    args: argparse.Namespace, sensitive_dirs: frozenset[str], logger: logging.Logger
) -> None:
    """Validate the output path, including the extra --inplace checks"""
    # Validated whenever the path will be used. The only skipped case is
    # --stdout without --dry-run, where args.output is never written.
    if _output_path_will_be_used(args):
        resolved = _validate_as_output_target(
            args.output, args, sensitive_dirs, logger,
            "[!] Error: Invalid output path: %s"
        )

        # Overwrite protection applies only when a write will actually happen
        if _would_overwrite_without_force(args, resolved):
            logger.error("[!] Error: Output file '%s' already exists. Use --force to overwrite.", args.output)
            sys.exit(1)

    # --inplace rewrites the input, so re-validate it under output rules
    if args.inplace:
        _validate_as_output_target(
            args.input, args, sensitive_dirs, logger,
            "[!] Error: Cannot use --inplace with this file: %s"
        )


def _validate_as_output_target(
    candidate: str, args: argparse.Namespace, sensitive_dirs: frozenset[str],
    logger: logging.Logger, error_template: str
) -> Path:
    """Validate a path under output rules, exiting on failure. Returns resolved"""
    valid, error, resolved = validate_file_path(
        candidate,
        allow_absolute=args.allow_absolute_paths,
        is_output=True,
        sensitive_dirs=sensitive_dirs
    )
    if not valid:
        logger.error(error_template, error)
        sys.exit(1)
    return resolved


def _resolve_keep_private_ips(args: argparse.Namespace) -> bool:
    """Decide whether non-global IPs are preserved

    --anonymise implies keeping them for better context unless the user was
    explicit either way.
    """
    # Default keep_private_ips to True when anonymise is used (better AI context)
    # unless explicitly disabled with --no-keep-private-ips
    if args.anonymise and args.keep_private_ips is None:
        # --anonymise without explicit --keep-private-ips or --no-keep-private-ips
        keep_private_ips = True
    elif args.keep_private_ips is None:
        # No anonymise, no explicit flag
        keep_private_ips = False
    else:
        # Explicit flag was used
        keep_private_ips = args.keep_private_ips
    return keep_private_ips


Allowlists = tuple[set[str], list[IPNetwork], set[str]]


def _merge_allowlist(target: Allowlists, parsed: Allowlists) -> None:
    """Fold one parsed (ips, networks, domains) triple into the accumulators

    Networks extend rather than update: they are a list because overlapping
    CIDRs are checked in order, not deduplicated.
    """
    ips, networks, domains = target
    parsed_ips, parsed_networks, parsed_domains = parsed
    ips.update(parsed_ips)
    networks.extend(parsed_networks)
    domains.update(parsed_domains)


def _load_default_allowlists(
    args: argparse.Namespace, logger: logging.Logger, target: Allowlists
) -> None:
    """Merge every default allow-list file found on disk, unless disabled"""
    if getattr(args, 'no_default_allowlist', False):
        return

    for default_file in find_default_allowlist_files():
        _merge_allowlist(target, parse_allowlist_file(default_file, silent_if_missing=True))
        if not args.dry_run and not args.stdout:
            logger.info("[+] Loaded default allow-list: %s", default_file)


def _collect_allowlists(
    args: argparse.Namespace, logger: logging.Logger
) -> Allowlists:
    """Merge allow-list entries from default files, --allowlist-file and CLI flags

    Sources are applied in order and all of them merge; a later source adds to
    the earlier ones rather than replacing them.
    """
    collected: Allowlists = (set(), [], set())

    _load_default_allowlists(args, logger, collected)

    if args.allowlist_file:
        _merge_allowlist(collected, parse_allowlist_file(args.allowlist_file, silent_if_missing=False))

    allowlist_ips, allowlist_networks, allowlist_domains = collected

    for entry in args.allowlist_ips or ():
        _add_cli_allowlist_ip(entry, allowlist_ips, allowlist_networks, logger)

    # Domains are compared case-insensitively
    for domain in args.allowlist_domains or ():
        allowlist_domains.add(domain.lower())

    return allowlist_ips, allowlist_networks, allowlist_domains


def _add_cli_allowlist_ip(
    entry: str, ips: set[str], networks: list[IPNetwork], logger: logging.Logger
) -> None:
    """Add one --allowlist-ip entry, exiting if it is neither an IP nor a CIDR

    Unlike allow-list *files*, where an unparseable line is treated as a
    domain, an explicit --allowlist-ip that does not parse is a user error and
    is fatal.
    """
    try:
        ipaddress.ip_address(entry)
        ips.add(entry)
        return
    except ValueError:
        pass

    try:
        networks.append(ipaddress.ip_network(entry, strict=False))
        return
    except ValueError:
        pass

    logger.error("[!] Error: Invalid IP or CIDR in --allowlist-ip: %s", entry)
    sys.exit(1)


def _handle_early_exit_flags(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Handle argument combinations that exit before any redaction happens"""
    if not args.check_version and not args.input:
        parser.error("the following arguments are required: input")

    if args.check_version:
        from .version_checker import print_version_check  # pylint: disable=import-outside-toplevel

        setup_logging(logging.INFO, use_stderr=False)
        success = print_version_check(verbose=False)
        sys.exit(0 if success else 1)

    if args.quiet and args.verbose:
        parser.error("--quiet and --verbose are mutually exclusive")


def _configure_logging_from_args(args: argparse.Namespace) -> None:
    """Set up logging at the verbosity the flags ask for

    --stdout routes everything to stderr so the redacted XML on stdout stays
    machine-readable.
    """
    if args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.WARNING
    else:
        log_level = logging.INFO

    setup_logging(log_level, use_stderr=args.stdout)


def _needs_generated_output_name(args: argparse.Namespace) -> bool:
    """Whether a destination has to be invented because none was given

    Every mode that writes somewhere else - stdout, in place, or nowhere at all
    under --dry-run - supplies its own destination.
    """
    if args.stdout or args.inplace:
        return False
    if args.dry_run:
        return False
    return not args.output


def _apply_argument_defaults(args: argparse.Namespace) -> None:
    """Fill in values implied by other flags, before any validation"""
    # --dry-run-verbose is a louder --dry-run
    if args.dry_run_verbose:
        args.dry_run = True

    # Auto-generate output filename when one is needed but not given
    if _needs_generated_output_name(args):
        input_path = Path(args.input)
        args.output = str(input_path.parent / f"{input_path.stem}-redacted{input_path.suffix}")


def main() -> None:
    """Main entry point for the pfSense redactor CLI"""
    # Version for the --version flag. Resolved rather than imported directly so
    # that running redactor.py as a script still reports the real version.
    __version__ = resolve_version()

    parser = _build_arg_parser(__version__)

    args = parser.parse_args()

    _handle_early_exit_flags(args, parser)
    _configure_logging_from_args(args)
    _apply_argument_defaults(args)

    # Get logger for error messages
    logger = logging.getLogger('pfsense_redactor')

    # Compute sensitive directories once for efficiency
    sensitive_dirs = _get_sensitive_directories()

    _resolve_input_path(args, sensitive_dirs, logger)
    _resolve_output_path(args, sensitive_dirs, logger)

    keep_private_ips = _resolve_keep_private_ips(args)

    allowlist_ips, allowlist_networks, allowlist_domains = _collect_allowlists(args, logger)

    # Create redactor and process file
    redactor = PfSenseRedactor(
        keep_private_ips=keep_private_ips,
        anonymise=args.anonymise,
        aggressive=args.aggressive,
        fail_on_warn=args.fail_on_warn,
        allowlist_ips=allowlist_ips,
        allowlist_domains=allowlist_domains,
        allowlist_networks=allowlist_networks,
        dry_run_verbose=args.dry_run_verbose,
        redact_url_usernames=args.redact_url_usernames,
        redact_descriptions=args.redact_descriptions
    )

    success = redactor.redact_config(
        args.input,
        args.output,
        redact_ips=not args.no_redact_ips,
        redact_domains=not args.no_redact_domains,
        dry_run=args.dry_run,
        stdout_mode=args.stdout,
        inplace=args.inplace
    )

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
