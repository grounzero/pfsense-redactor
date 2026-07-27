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
would end that, so there are none; the only package-relative import is the
optional __version__ lookup in resolve_version(), which falls back cleanly.

Guarded by tests/integration/test_standalone_script.py, and by the C0302
disable in .pylintrc.

Layout
------
Sections below are marked with banner comments, in this order:

    1. Logging          ColouredFormatter, setup_logging
    2. Constants        element sets, secret/cert tag patterns, deny-list
    3. Version          resolve_version
    4. Redactor         PfSenseRedactor - the bulk of the file
    5. Allowlists       allow-list file parsing
    6. Path safety      path traversal / sensitive directory validation
    7. CLI              argparse wiring and main()
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
import argparse
import re
import sys
import ipaddress
import functools
import logging
from pathlib import Path
from collections import defaultdict
from collections.abc import Callable
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

    def format(self, record):
        """Format log record with colours if outputting to a TTY

        Note: We colour the final formatted string rather than mutating
        the record to avoid issues with multiple handlers.
        """
        # Get the formatted message without colours
        formatted = super().format(record)

        # Only add colours if outputting to a TTY
        if self.stream and hasattr(self.stream, 'isatty') and self.stream.isatty():
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
SECRET_TAG_PATTERN = re.compile(
    r'passw(?:or)?d|passphrase|(?:^|[_-])pass(?:$|[_-])'
    r'|psk|pre-?shared-?key|shared-?key'
    r'|secret|token|community|credential|bindpw|licen[cs]e|webhook'
    r'|api[_-]?key|account-?key|authorized-?keys'
    r'|priv(?:ate)?[_-]?key|key(?:s)?$|[_-]key\d*$',
    re.IGNORECASE
)

# Certificate-ish tags are redacted only when the content actually looks like
# PEM/blob material, so short certificate *references* (refid-style IDs, which
# are useful for understanding config structure) survive intact.
CERT_TAG_PATTERN = re.compile(r'cert(?:ificate)?s?$|ssloffload', re.IGNORECASE)

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
})

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


def is_rfc_documentation_ip(ip: IPAddress) -> bool:
    """Check whether an address is in a reserved documentation range

    Shared by the three places that need it: _mask_ip_like_tokens,
    _is_already_masked_host and _normalise_masked_url. Each previously inlined
    its own copy and rebuilt the network objects on every call.
    """
    if ip.version == 4:
        return any(ip in net for net in RFC_DOC_NETWORKS_V4)
    return ip in RFC_DOC_NETWORK_V6

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

# Compile regex for sensitive attribute matching (anchored patterns to avoid false positives)
# Use word boundaries (\b) to match whole words or common separators (-, _)
SENSITIVE_ATTR_PATTERN = re.compile(
    r'\b(?:password|passwd|pass|key|secret|token|bearer|cookie|'
    r'client[_-]?secret|client[_-]?key|api[_-]?key|apikey|'
    r'auth(?:_key|_token|entication)?|signature)\b',
    re.IGNORECASE
)


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


# ==========================================================================
# 4. REDACTOR
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

        # Get logger instance
        self.logger = logging.getLogger('pfsense_redactor')

        # ReDoS protection constants (instance attributes for easy access)
        self.MAX_URL_LENGTH: int = 2048  # RFC 2616 suggests 2048 as reasonable max
        self.MAX_EMAIL_LENGTH: int = 320  # RFC 5321: 64 (local) + @ + 255 (domain)
        self.MAX_FQDN_LENGTH: int = 253  # RFC 1035: max DNS name length
        self.MAX_TEXT_CHUNK: int = 1048576  # 1MB max for any text element

        # Allow-lists (opt-in, empty by default)
        # IP allow-lists: support both individual IPs and CIDR networks
        self.allowlist_ip_addrs: set[IPAddress] = set()
        if allowlist_ips:
            for ip_str in allowlist_ips:
                try:
                    self.allowlist_ip_addrs.add(ipaddress.ip_address(ip_str))
                except ValueError:
                    pass  # Will be handled as network or error elsewhere

        self.allowlist_ip_networks: list[IPNetwork] = []
        if allowlist_networks:
            self.allowlist_ip_networks = list(allowlist_networks)

        # Domain allow-lists: store both normalised Unicode and IDNA forms
        self.allowlist_domains: set[str] = set()
        self.allowlist_domains_idna: set[str] = set()
        if allowlist_domains:
            for domain in allowlist_domains:
                norm_domain, idna_domain = self._normalise_domain(domain)
                # Skip invalid/empty domains (returns None, None)
                if norm_domain is not None:
                    self.allowlist_domains.add(norm_domain)
                    if idna_domain and idna_domain != norm_domain:
                        self.allowlist_domains_idna.add(idna_domain)

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
        self.IP_PATTERN = re.compile(r'^[\[\]]?[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.:+-]+)?[\[\]]?(?::\d+)?$')
        self._ip_token_splitter = re.compile(r'([^0-9A-Za-z\.\:\[\]_+-])')

        # PEM marker detection
        self.PEM_MARKER = re.compile(
            r'-----BEGIN (?:CERTIFICATE|RSA PRIVATE KEY|EC PRIVATE KEY|ENCRYPTED PRIVATE KEY|PRIVATE KEY|PUBLIC KEY|OPENVPN STATIC KEY|OPENSSH PRIVATE KEY)-----'
        )

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

        # Check exact match or suffix match against Unicode forms
        for allow_domain in self.allowlist_domains:
            if host_l == allow_domain or host_l.endswith('.' + allow_domain):
                return True

        # Check exact match or suffix match against IDNA forms
        for allow_domain_idna in self.allowlist_domains_idna:
            if host_idna == allow_domain_idna or host_idna.endswith('.' + allow_domain_idna):
                return True

        return False

    def _is_ip_allowed(self, ip: IPAddress) -> bool:
        """Check if an IP address is in the allow-list (including CIDR networks)"""
        if ip in self.allowlist_ip_addrs:
            return True
        return any(ip in net for net in self.allowlist_ip_networks)

    def _mask_ip_sample(self, value: str) -> str:
        """Mask IP address for sample display"""
        try:
            ip = ipaddress.ip_address(value)
            if ip.version == 4:
                parts = value.split('.')
                if len(parts) == 4:
                    return f"{parts[0]}.{parts[1]}.***.{parts[3]}"
            else:
                parts = value.split(':')
                if len(parts) >= 3:
                    return f"{parts[0]}:{parts[1]}:*:****::{parts[-1]}"
        except ValueError:
            pass
        return value

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

            userinfo = ''
            if parts.username:
                userinfo = f"{parts.username}:***@" if parts.password else f"{parts.username}@"
            netloc = f"{userinfo}{masked_host}"
            if parts.port:
                netloc += f":{parts.port}"

            # Credentials also live in the path and query, not just userinfo
            safe_path, _ = self._build_redacted_path(parts.path)
            safe_query, _ = self._build_redacted_query(parts.query)

            if '[' in masked_host:
                result = f"{parts.scheme}://{netloc}{safe_path}"
                if safe_query:
                    result += f"?{safe_query}"
                if parts.fragment:
                    result += f"#{parts.fragment}"
                return result
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

    def _mask_mac_sample(self, value: str) -> str:
        """Mask MAC address for sample display"""
        if ':' in value:
            parts = value.split(':')
            if len(parts) == 6:
                return f"{parts[0]}:{parts[1]}:**:**:{parts[4]}:{parts[5]}"
        elif '.' in value:
            parts = value.split('.')
            if len(parts) == 3:
                return f"{parts[0]}.****.{parts[2]}"
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
        overflow = counter - 0xFFFF
        hextet3 = ((overflow - 1) % 0x10000) + 1
        hextet2 = (overflow - 1) // 0x10000
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

    def _mask_ip_like_tokens(self, text: str) -> str:
        """IP address masking using ipaddress module"""
        def repl(token: str) -> str:
            # Skip already-masked tokens
            if token in ('XXX.XXX.XXX.XXX', 'XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX', '[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]'):
                return token
            original_token = token

            token, port_suffix = self._strip_ip_token_port(token)

            ip, bracketed, zone = self._parse_ip_token(token)
            if ip is None:
                return original_token

            if self._should_preserve_ip(ip):
                return original_token

            # Anonymisation mode
            if self.anonymise:
                rep = self._anonymise_ip(str(ip))
            else:
                # Standard redaction
                rep = 'XXX.XXX.XXX.XXX' if ip.version == 4 else 'XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX'

            # Preserve zone identifier if present
            if zone:
                rep = f"{rep}%{zone}"
            if bracketed:
                rep = f"[{rep}]"

            result = rep + port_suffix

            # Only count if actually changed
            if result != original_token:
                self.stats['ips_redacted'] += 1
                # Collect sample for dry-run-verbose
                self._add_sample('IP', str(ip), rep)

            return result

        # Split conservatively - matches IP-like tokens including zone IDs and ports
        # Pattern matches: IPs with optional brackets, zone identifiers, and ports
        # Examples: [fe80::1%eth0]:51820, [fe80::1%eth0], fe80::1%eth0, 192.168.1.1
        parts = self._ip_token_splitter.split(text)
        # Match tokens that look like IPs (with or without brackets/zones/ports)
        # Use pre-compiled pattern for consistency and performance
        return ''.join(repl(p) if self.IP_PATTERN.match(p) else p for p in parts)

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

    def _build_netloc(self, parts: SplitResult, host: str, is_ipv6: bool) -> str:
        """Build netloc with userinfo, host, and port"""
        userinfo = ''
        if parts.username:
            if self.redact_url_usernames:
                userinfo = 'REDACTED'
            else:
                userinfo = parts.username
            if parts.password:
                userinfo += ':REDACTED'
            userinfo += '@'

        # Wrap IPv6 in brackets
        if is_ipv6 or (':' in host and not host.startswith('[')):
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
            if value and name_l not in SECRET_TAG_DENYLIST and SECRET_TAG_PATTERN.search(name_l):
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
    def _is_secretish_path_segment(segment: str) -> bool:
        """Check whether a URL path segment looks like an embedded credential

        Uses a lower length floor than _is_high_entropy_value: webhook tokens
        sit around 20-24 chars, below the threshold used for key material.

        Boundaries here are load-bearing, so each is justified:

        - >= 20, not > 20. AWS access key IDs (AKIA...) are exactly 20
          characters, so a > 20 test excluded the entire format.
        - Colon-separated segments are split first. Telegram bot tokens are
          'bot<id>:<secret>', and the colon fails BASE64ISH_RE, which let a
          47-character credential through as an ordinary path segment.
        - A digit is required only below DIGITLESS_TOKEN_LENGTH. The digit rule
          exists to protect underscore-joined route names such as
          'Open_VM_Tools_package' (21 chars); beyond that length an all-letter
          segment is far more likely to be a token than a route. Requiring a
          digit unconditionally silently missed alphabetic Slack tokens.
        """
        for part in segment.split(':'):
            if len(part) < SECRETISH_SEGMENT_MIN_LENGTH:
                continue
            if not BASE64ISH_RE.match(part):
                continue

            has_letter = any(c.isalpha() for c in part)
            has_digit = any(c.isdigit() for c in part)
            if not has_letter:
                continue
            if has_digit or len(part) >= DIGITLESS_TOKEN_LENGTH:
                return True

        return False

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
        """Redact long high-entropy path segments (aggressive mode only)

        Slack/Discord-style webhooks carry the credential as a path segment
        rather than a query parameter. Gated behind --aggressive because feed
        URLs legitimately carry long path segments.
        """
        redacted, changed = self._build_redacted_path(path)
        if changed:
            self.stats['url_secrets_redacted'] += 1
        return redacted

    def _rebuild_url(self, parts: SplitResult, masked_host: str, is_ipv6: bool) -> str:
        """Rebuild URL from parts with masked host"""
        netloc = self._build_netloc(parts, masked_host, is_ipv6)

        path = parts.path
        query = self._redact_query_secrets(parts.query)
        if self.aggressive:
            path = self._redact_path_secrets(path)

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
        def replacer(match):
            url = match.group(0)
            if len(url) > self.MAX_URL_LENGTH:
                return url

            parts = self._parse_url_safely(url)
            if parts is None or not parts.netloc:
                return url

            netloc, netloc_changed = self._redact_netloc_userinfo(parts)
            path = self._redact_path_secrets(parts.path) if self.aggressive else parts.path
            query = self._redact_query_secrets(parts.query)

            # netloc_changed must be part of this test: a URL carrying
            # credentials but no secret-named query parameter would otherwise
            # never be rewritten at all.
            if not netloc_changed and path == parts.path and query == parts.query:
                return url

            if netloc_changed:
                self.stats['url_secrets_redacted'] += 1

            return urlunsplit((parts.scheme, netloc, path, query, parts.fragment))

        return self.URL_RE.sub(replacer, text)

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

    def _should_redact_completely(
        self, tag: str, tag_base: str, element: ET.Element, redact_ips: bool, redact_domains: bool
    ) -> bool:
        """Check if element should be completely redacted and handle it. Returns True if handled."""
        if not self._is_secret_tag(tag, tag_base):
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
            self.redact_element(child, redact_ips, redact_domains)

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

        Stricter than _looks_like_secret_blob: requires the whole value to be
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
        if len(compact) < BLOB_MIN_SCAN_LENGTH or ' ' in compact or '\t' in compact:
            return False

        if not (BASE64ISH_RE.match(compact) or HEXISH_RE.match(compact)):
            return False

        # Require some mix of character classes so that long runs of a single
        # class (e.g. a numeric ID, or a lowercase-only word) are not flagged.
        has_digit = any(c.isdigit() for c in compact)
        has_upper = any(c.isupper() for c in compact)
        has_lower = any(c.islower() for c in compact)
        if HEXISH_RE.match(compact):
            return has_digit and (has_upper or has_lower)
        return has_digit + has_upper + has_lower >= 2

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

    def _redact_unknown_blob_element(self, tag: str, element: ET.Element) -> bool:
        """Handle high-entropy values in elements we do not otherwise recognise

        Default: record the value's location so users can audit it manually.
        --aggressive: redact it.

        The <key> handler already covers its own tag; everything else previously
        sailed through regardless of how much it looked like key material.
        """
        if tag == 'key' or len(element) > 0:
            return False
        if not element.text:
            return False

        text = element.text.strip()
        if not self._is_high_entropy_value(text):
            return False

        # _path_stack holds ancestors only; this element's own tag completes it
        path = '/'.join([*self._path_stack, tag])

        if self.aggressive:
            self._redact_text_and_track(element, 'Cert/Key', '[REDACTED_CERT_OR_KEY]')
            return True

        self.stats['high_entropy_retained'] += 1
        if path not in self.high_entropy_paths:
            self.high_entropy_paths.append(path)
        return False

    def _redact_key_element_if_needed(self, tag: str, element: ET.Element, redact_ips: bool, redact_domains: bool) -> bool:
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
            self.redact_element(child, redact_ips, redact_domains)

        return True

    def _redact_cert_key_element(self, tag: str, tag_base: str, element: ET.Element) -> bool:
        """Redact certificate/key elements. Returns True if this is a cert/key element."""
        if not self._is_cert_tag(tag, tag_base):
            return False

        # Use class constant for minimum certificate length
        if element.text and (self.PEM_MARKER.search(element.text) or
                            len(element.text.strip()) > self.CERT_MIN_LENGTH):
            self._redact_text_and_track(element, 'Cert/Key', '[REDACTED_CERT_OR_KEY]')

        return True

    def _redact_ip_containing_element(
        self, tag: str, tag_base: str, element: ET.Element, redact_ips: bool, redact_domains: bool
    ) -> bool:
        """Redact IPs/domains in known IP-containing elements. Returns True if processed."""
        if (tag in self.ip_containing_elements or tag_base in self.ip_containing_elements):
            if element.text:
                element.text = self.redact_text(element.text, redact_ips, redact_domains)
                return True
        return False

    def _redact_sensitive_attributes(self, element: ET.Element) -> None:
        """Redact attributes with sensitive names using anchored regex patterns"""
        for attr in list(element.attrib.keys()):
            if SENSITIVE_ATTR_PATTERN.search(attr):
                original = element.attrib[attr]
                element.attrib[attr] = '[REDACTED]'
                self.stats['secrets_redacted'] += 1
                self._add_sample('Secret', original, '[REDACTED]')

    def _redact_text_aggressive(
        self, element: ET.Element, text_already_processed: bool, redact_ips: bool, redact_domains: bool
    ) -> None:
        """Redact text and attributes in aggressive mode"""
        tag = self._normalise_tag(element.tag)
        if self._is_secret_tag(tag, self._get_tag_base(tag)):
            return

        # Process text if not already done
        if element.text and not text_already_processed:
            element.text = self.redact_text(element.text, redact_ips, redact_domains)

        # Process tail
        if element.tail:
            element.tail = self.redact_text(element.tail, redact_ips, redact_domains)

        # Process attributes
        for attr in list(element.attrib.keys()):
            if element.attrib[attr]:
                element.attrib[attr] = self.redact_text(
                    element.attrib[attr], redact_ips, redact_domains
                )

    def redact_element(self, element: ET.Element, redact_ips: bool = True, redact_domains: bool = True) -> None:
        """Recursively redact sensitive information from XML element"""

        # Normalise tag name to handle namespaced exports
        tag = self._normalise_tag(element.tag)

        # Strip trailing digits from tag to handle numbered variants (e.g., dnsserver6 -> dnsserver)
        tag_base = self._get_tag_base(tag)

        # <key> is handled specially (PEM blob vs short secret) and must be
        # checked before the generic secret match, which would otherwise claim
        # it via SECRET_TAG_PATTERN and lose the cert/key distinction.
        if self._redact_key_element_if_needed(tag, element, redact_ips, redact_domains):
            return

        # Handle complete redaction cases
        if self._should_redact_completely(tag, tag_base, element, redact_ips, redact_domains):
            return

        # Handle cert/key elements (don't return - continue to process children)
        self._redact_cert_key_element(tag, tag_base, element)

        # Opaque free-text containers (custom_options, upsd_users, ...) that
        # carry credentials inline rather than in dedicated elements
        text_already_processed = self._redact_blob_text_element(tag, tag_base, element)

        # Descriptions/identifiers - opt-in via --redact-descriptions
        if self._redact_description_element(tag, tag_base, element):
            text_already_processed = True

        # Unrecognised high-entropy leaf values (third-party package fields)
        if self._redact_unknown_blob_element(tag, element):
            text_already_processed = True

        # Track whether we already processed text to avoid double processing in aggressive mode
        if self._redact_ip_containing_element(tag, tag_base, element, redact_ips, redact_domains):
            text_already_processed = True

        # Credentials embedded in URLs in elements that are not known URL
        # carriers (e.g. <updateurl>, <webhook_url>). Previously these were
        # only touched under --aggressive, so the token survived by default.
        # Host anonymisation deliberately stays out of the default path here.
        if element.text and not text_already_processed and '://' in element.text:
            element.text = self._redact_url_secrets_only(element.text)

        # Redact attributes with sensitive names
        self._redact_sensitive_attributes(element)

        # Recursively process child elements
        self._path_stack.append(tag)
        try:
            for child in element:
                self.redact_element(child, redact_ips, redact_domains)
        finally:
            self._path_stack.pop()

        # Aggressive mode: apply redaction to text content, tail, and attributes
        if self.aggressive:
            self._redact_text_aggressive(element, text_already_processed, redact_ips, redact_domains)

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
            # Parse XML
            tree = ET.parse(input_file)
            root = tree.getroot()

            if not self._check_root_tag(root):
                return False

            if not dry_run and not stdout_mode:
                self.logger.info("[+] Parsing XML configuration from: %s", input_file)

            # Redact the configuration
            if not dry_run and not stdout_mode:
                self.logger.info("[+] Redacting sensitive information...")
            self.redact_element(root, redact_ips, redact_domains)

            # Dry run mode: just print stats
            if dry_run:
                self.logger.info("[+] Dry run - no files modified")
                self._print_stats()
                return True

            # Add redaction comment to the root element
            self._add_redaction_comment(root)

            # Pretty print (Python 3.9+)
            ET.indent(tree, space="  ")

            self._write_output(tree, input_file, output_file, stdout_mode, inplace)

            # Print summary (always print, logger routes to correct stream)
            self._print_stats()

            return True

        except ET.ParseError as e:
            self.logger.error("[!] Error parsing XML: %s", e)
            return False
        except (IOError, OSError) as e:
            self.logger.error("[!] Error reading/writing file: %s", e)
            return False
        except (ValueError, TypeError) as e:
            self.logger.error("[!] Error processing configuration: %s", e)
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
# 5. ALLOWLISTS
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
# 6. PATH SAFETY
# ==========================================================================
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

    # Windows system directories
    windows_sensitive_dirs = {
        'c:\\windows', 'c:\\windows\\system32', 'c:\\program files',
        'c:\\program files (x86)', 'c:\\programdata',
    }

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

    return frozenset(normalised)


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

        # Check if this looks like a Windows absolute path (e.g., C:\, D:\)
        # On Unix systems, Path.is_absolute() returns False for Windows paths
        is_windows_absolute = (
            len(file_path) >= 3 and
            file_path[1:3] in (':\\', ':/')  # C:\ or C:/
        )

        # Resolve the path to its absolute form (follows symlinks)
        # Use Path.cwd() as base for relative paths
        if path.is_absolute() or is_windows_absolute:
            resolved = path.resolve()
        else:
            # For relative paths, resolve against current working directory
            resolved = (Path.cwd() / path).resolve()

        resolved_str = str(resolved).lower()

        # Check if resolved path is in a sensitive directory FIRST
        # This is the critical security check - do it before the absolute path check
        # so that even with --allow-absolute-paths, we still block sensitive dirs
        if is_output:
            for sensitive_dir in sensitive_dirs:
                # Check if resolved path is within or equal to sensitive directory
                try:
                    # Use is_relative_to for Python 3.9+
                    if resolved_str.startswith(sensitive_dir):
                        return False, f"Cannot write to sensitive system directory: {resolved}", None
                except (ValueError, AttributeError):
                    pass

        # Check if absolute path is allowed (after sensitive dir check)
        # Allow absolute paths to safe locations (like temp dirs, home, cwd)
        if (path.is_absolute() or is_windows_absolute) and not allow_absolute:
            # Normalise resolved path for comparison (convert backslashes to forward slashes)
            resolved_normalised = resolved_str.replace('\\', '/')

            # Check if this is a "safe" absolute path (temp dir, home, or under cwd)
            # Normalise all safe prefixes to use forward slashes for consistent comparison
            safe_prefixes_raw = [
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

            # Normalise all safe prefixes to use forward slashes
            safe_prefixes_normalised = [prefix.replace('\\', '/') for prefix in safe_prefixes_raw]

            # Check if path is under CWD
            cwd_normalised = str(Path.cwd()).lower().replace('\\', '/')

            # Ensure CWD ends with separator for proper prefix matching
            if not cwd_normalised.endswith('/'):
                cwd_normalised += '/'

            is_under_cwd = resolved_normalised.startswith(cwd_normalised) or resolved_normalised == cwd_normalised.rstrip('/')

            # Check other safe prefixes (also normalised)
            is_under_safe_prefix = any(
                resolved_normalised.startswith(prefix if prefix.endswith('/') else prefix + '/')
                for prefix in safe_prefixes_normalised
            )

            is_safe = is_under_cwd or is_under_safe_prefix

            if not is_safe:
                return False, f"Absolute paths not allowed (use --allow-absolute-paths): {file_path}", None

        # Additional check: ensure we're not trying to write to system config files
        if is_output:
            dangerous_files = {
                '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
                '/etc/hosts', '/etc/fstab', '/etc/crontab',
                'c:\\windows\\system32\\config\\sam',
                'c:\\windows\\system32\\config\\system',
            }
            if resolved_str in {f.lower() for f in dangerous_files}:
                return False, f"Cannot write to system configuration file: {resolved}", None

        return True, "", resolved

    except (OSError, RuntimeError, ValueError) as e:
        return False, f"Error validating path: {e}", None




# ==========================================================================
# 7. CLI
# ==========================================================================
def main() -> None:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """Main entry point for the pfSense redactor CLI"""
    # Version for the --version flag. Resolved rather than imported directly so
    # that running redactor.py as a script still reports the real version.
    __version__ = resolve_version()

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

    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}',
                        help='Show program version and exit')
    parser.add_argument('--check-version', action='store_true',
                        help='Check for updates from PyPI')

    parser.add_argument('input', nargs='?', help='Input pfSense config.xml file (required unless --check-version is used)')
    parser.add_argument('output', nargs='?', help='Output redacted config.xml file')
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

    args = parser.parse_args()

    # Validate required arguments for normal operation
    if not args.check_version and not args.input:
        parser.error("the following arguments are required: input")

    # Handle --check-version flag
    if args.check_version:
        # Import version checker
        from .version_checker import print_version_check

        # Setup basic logging for version check
        setup_logging(logging.INFO, use_stderr=False)

        # Run version check and exit
        success = print_version_check(verbose=False)
        sys.exit(0 if success else 1)

    # Validate mutually exclusive flags
    if args.quiet and args.verbose:
        parser.error("--quiet and --verbose are mutually exclusive")

    # Determine log level
    if args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.WARNING
    else:
        log_level = logging.INFO

    # Setup logging (route to stderr when using --stdout)
    use_stderr = args.stdout
    setup_logging(log_level, use_stderr)

    # Handle --dry-run-verbose
    if args.dry_run_verbose:
        args.dry_run = True

    # Default output filename if not specified
    if not args.stdout and not args.inplace and not args.dry_run and not args.output:
        # Auto-generate output filename: input-redacted.xml
        input_path = Path(args.input)
        args.output = str(input_path.parent / f"{input_path.stem}-redacted{input_path.suffix}")

    # Get logger for error messages
    logger = logging.getLogger('pfsense_redactor')

    # Compute sensitive directories once for efficiency
    sensitive_dirs = _get_sensitive_directories()

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

    # Validate output file path (if applicable)
    # Skip validation in dry-run mode since we won't actually write
    if args.output and not args.stdout and not args.dry_run:
        output_valid, output_error, output_resolved = validate_file_path(
            args.output,
            allow_absolute=args.allow_absolute_paths,
            is_output=True,
            sensitive_dirs=sensitive_dirs
        )
        if not output_valid:
            logger.error("[!] Error: Invalid output path: %s", output_error)
            sys.exit(1)

        # Check if output file exists (unless force)
        if not args.force and output_resolved.exists():
            logger.error("[!] Error: Output file '%s' already exists. Use --force to overwrite.", args.output)
            sys.exit(1)
    elif args.dry_run and args.output:
        # In dry-run mode, still validate the output path for security
        output_valid, output_error, _ = validate_file_path(
            args.output,
            allow_absolute=args.allow_absolute_paths,
            is_output=True,
            sensitive_dirs=sensitive_dirs
        )
        if not output_valid:
            logger.error("[!] Error: Invalid output path: %s", output_error)
            sys.exit(1)

    # Validate inplace mode - extra security check
    if args.inplace:
        # Re-validate input path with output restrictions
        inplace_valid, inplace_error, _ = validate_file_path(
            args.input,
            allow_absolute=args.allow_absolute_paths,
            is_output=True,  # Treat as output for stricter checks
            sensitive_dirs=sensitive_dirs
        )
        if not inplace_valid:
            logger.error("[!] Error: Cannot use --inplace with this file: %s", inplace_error)
            sys.exit(1)

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

    # Build allow-lists from multiple sources (merge all)
    allowlist_ips = set()
    allowlist_networks = []
    allowlist_domains = set()

    # 1. Load default allow-list files (unless disabled)
    if not getattr(args, 'no_default_allowlist', False):
        default_files = find_default_allowlist_files()
        for default_file in default_files:
            file_ips, file_networks, file_domains = parse_allowlist_file(default_file, silent_if_missing=True)
            allowlist_ips.update(file_ips)
            allowlist_networks.extend(file_networks)
            allowlist_domains.update(file_domains)
            if not args.dry_run and not args.stdout:
                logger.info("[+] Loaded default allow-list: %s", default_file)

    # 2. Load explicit allow-list file if provided
    if args.allowlist_file:
        file_ips, file_networks, file_domains = parse_allowlist_file(args.allowlist_file, silent_if_missing=False)
        allowlist_ips.update(file_ips)
        allowlist_networks.extend(file_networks)
        allowlist_domains.update(file_domains)

    # 3. Add IPs/CIDRs from CLI
    if args.allowlist_ips:
        for entry in args.allowlist_ips:
            # Try as single IP first
            try:
                ipaddress.ip_address(entry)
                allowlist_ips.add(entry)
                continue
            except ValueError:
                pass

            # Try as CIDR network
            try:
                network = ipaddress.ip_network(entry, strict=False)
                allowlist_networks.append(network)
                continue
            except ValueError:
                pass

            # Invalid entry
            logger.error("[!] Error: Invalid IP or CIDR in --allowlist-ip: %s", entry)
            sys.exit(1)

    # 4. Add domains from CLI (case-insensitive)
    if args.allowlist_domains:
        for domain in args.allowlist_domains:
            allowlist_domains.add(domain.lower())

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
