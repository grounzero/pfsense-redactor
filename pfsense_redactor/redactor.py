"""
pfSense XML Configuration Redactor
Redacts sensitive information from pfSense config.xml files
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
from typing import Union
from urllib.parse import urlsplit, urlunsplit, SplitResult

# Type aliases for clarity (using Union for Python 3.9 compatibility)
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


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


class PfSenseRedactor:  # pylint: disable=too-many-instance-attributes
    """pfSense configuration redactor for sensitive data handling

    Note: This class intentionally has many instance attributes to maintain
    clear separation of concerns and avoid premature optimization. The attributes
    are logically grouped and well-documented.
    """

    # Class constants for magic numbers
    SAMPLE_LIMIT: int = 5  # Maximum number of samples to collect per category
    CERT_MIN_LENGTH: int = 50  # Minimum length to treat text as certificate/key blob
    KEY_BLOB_MIN_LENGTH: int = 64  # Minimum length to treat <key> content as PEM blob
    KEY_SHORT_THRESHOLD: int = 40  # Threshold for short key detection (alphanumeric check)

    def __init__(
        self,
        keep_private_ips: bool = False,
        anonymise: bool = False,
        aggressive: bool = False,
        fail_on_warn: bool = False,
        allowlist_ips: set[str] | None = None,
        allowlist_domains: set[str] | None = None,
        allowlist_networks: list[IPNetwork] | None = None,
        dry_run_verbose: bool = False,
        redact_url_usernames: bool = False
    ) -> None:
        self.keep_private_ips = keep_private_ips
        self.anonymise = anonymise
        self.aggressive = aggressive
        self.fail_on_warn = fail_on_warn
        self.dry_run_verbose = dry_run_verbose
        self.redact_url_usernames = redact_url_usernames

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
        # Also reject domains with internal whitespace
        if not domain_lower or ' ' in domain_lower:
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

    def _mask_url_sample(self, value: str) -> str:
        """Mask URL for sample display"""
        try:
            parts = urlsplit(value)
            host = parts.hostname or ''
            if not host:
                return value

            try:
                ip = ipaddress.ip_address(host)
                if ip.version == 4:
                    host_parts = host.split('.')
                    masked_host = f"{host_parts[0]}.{host_parts[1]}.***.{host_parts[3]}" if len(host_parts) == 4 else host
                else:
                    host_parts = host.split(':')
                    masked_host = f"[{host_parts[0]}:{host_parts[1]}:*:****::{host_parts[-1]}]" if len(host_parts) >= 3 else f"[{host}]"
            except (ValueError, ipaddress.AddressValueError):
                host_parts = host.split('.')
                if len(host_parts) >= 3:
                    masked_host = f"{host_parts[0]}.***.{'.'.join(host_parts[-2:])}"
                elif len(host_parts) == 2:
                    masked_host = f"***.{host}"
                else:
                    masked_host = host

            userinfo = ''
            if parts.username:
                userinfo = f"{parts.username}:***@" if parts.password else f"{parts.username}@"
            netloc = f"{userinfo}{masked_host}"
            if parts.port:
                netloc += f":{parts.port}"

            if '[' in masked_host:
                result = f"{parts.scheme}://{netloc}{parts.path}"
                if parts.query:
                    result += f"?{parts.query}"
                if parts.fragment:
                    result += f"#{parts.fragment}"
                return result
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
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
        """Generate a consistent alias for an IP address"""
        if ip_str not in self.ip_aliases:
            self.ip_counter += 1
            self.ip_aliases[ip_str] = f"IP_{self.ip_counter}"
        return self.ip_aliases[ip_str]

    def _counter_to_rfc_ip(self, counter: int, is_ipv6: bool) -> str:
        """Convert counter to RFC documentation IP address

        Maps counter values to sequential IPs within RFC documentation ranges:
        - IPv4: RFC 5737 ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
        - IPv6: RFC 3849 range (2001:db8::/32)

        Args:
            counter: The IP counter value (1-based)
            is_ipv6: True for IPv6, False for IPv4

        Returns:
            str: RFC documentation IP address
        """
        if is_ipv6:
            # RFC 3849: 2001:db8::/32
            # Map counter to last hextet (1..65535), wrapping if needed
            # Produces addresses like 2001:db8::1, 2001:db8::2, ..., 2001:db8::ffff
            hextet = (counter - 1) % 0xFFFF + 1
            return f"2001:db8::{hextet:x}"

        # RFC 5737 IPv4 documentation ranges (768 total addresses):
        # - 192.0.2.0/24 (TEST-NET-1): 254 usable
        # - 198.51.100.0/24 (TEST-NET-2): 254 usable
        # - 203.0.113.0/24 (TEST-NET-3): 254 usable
        # Skip .0 and .255 in each range (network/broadcast)

        if counter <= 254:
            # First range: 192.0.2.1 to 192.0.2.254
            return f"192.0.2.{counter}"
        if counter <= 508:
            # Second range: 198.51.100.1 to 198.51.100.254
            return f"198.51.100.{counter - 254}"
        if counter <= 762:
            # Third range: 203.0.113.1 to 203.0.113.254
            return f"203.0.113.{counter - 508}"
        # Wrap around if we exceed available addresses
        # This is unlikely in practice but provides graceful handling
        wrapped = ((counter - 1) % 762) + 1
        return self._counter_to_rfc_ip(wrapped, False)

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
        return self._counter_to_rfc_ip(counter, is_ipv6)

    def _mask_ip_like_tokens(self, text: str) -> str:
        """IP address masking using ipaddress module"""
        def repl(token: str) -> str:
            # Skip already-masked tokens
            if token in ('XXX.XXX.XXX.XXX', 'XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX', '[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]'):
                return token
            original_token = token

            # Extract optional trailing :port for unbracketed tokens
            # IPv6 must use brackets to carry a port; we only peel :port when the token contains a dot
            # Only strip port if it looks like IPv4:port (has dots)
            # Don't strip from IPv6 addresses (they use colons as part of the address)
            port_suffix = ''
            if not token.startswith('['):
                m_port = re.match(r'^(.*?)(:\d{1,5})$', token)
                if m_port:
                    potential_ip, potential_port = m_port.group(1), m_port.group(2)
                    # Only treat as port if it's a valid IPv4 address
                    # This prevents stripping ports from non-IP tokens like "foo.bar.baz:8080"
                    if '.' in potential_ip:
                        try:
                            ipaddress.ip_address(potential_ip)
                            token, port_suffix = potential_ip, potential_port
                        except ValueError:
                            pass  # Not a valid IP, don't strip port

            # Handle bracketed IPv6 with optional zone identifier and port: [fe80::1%em0]:51820
            # This handles: [IPv6], [IPv6%zone], [IPv6]:port, [IPv6%zone]:port
            if token.startswith('['):
                # Pattern match for bracketed IPv6 with port
                if ']:' in token:
                    # Extract port from bracketed IPv6
                    bracket_end = token.index(']:')
                    port_suffix = token[bracket_end+1:]  # Includes the colon
                    token = token[:bracket_end+1]  # Keep just [IPv6%zone]

            ip, bracketed, zone = self._parse_ip_token(token)
            if ip is None:
                return original_token

            # Always preserve common netmasks and unspecified addresses for readability
            # (regardless of --keep-private-ips setting)
            if str(ip) in self.always_preserve_ips:
                return original_token

            # Preserve allow-listed IPs (opt-in, including CIDR networks)
            if self._is_ip_allowed(ip):
                return original_token

            # Keep non-global IPs if requested (simplified test for RFC1918, ULA, loopback,
            # link-local, multicast, reserved, and unspecified addresses)
            if self.keep_private_ips and not ip.is_global:
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
        """Check if hostname is already a masked value"""
        if host in ('XXX.XXX.XXX.XXX',
                    'XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX',
                    'example.com'):
            return True
        return bool(self.anonymise and re.fullmatch(r'domain\d+\.example', host))

    def _normalise_masked_url(self, parts: SplitResult, host: str) -> str:
        """Normalise already-masked URLs to use example.com (or alias in anonymise mode)"""
        # In anonymise mode, use a consistent alias for masked URLs
        masked_host = self._anonymise_domain('example.com') if self.anonymise else 'example.com'

        if host == masked_host:
            return urlunsplit(parts)

        # Replace IP masks with example.com (or alias)
        netloc = self._build_netloc(parts, masked_host, False)
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))

    def _mask_url_host(self, host: str) -> tuple[str, bool, bool]:
        """Mask URL host. Returns (masked_host, changed, is_ipv6)"""
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
        if parts.port:
            netloc += f":{parts.port}"

        return netloc

    def _rebuild_url(self, parts: SplitResult, masked_host: str, is_ipv6: bool) -> str:
        """Rebuild URL from parts with masked host"""
        netloc = self._build_netloc(parts, masked_host, is_ipv6)

        # Manual construction for masked IPv6 (urlunsplit doesn't like invalid IPv6)
        if is_ipv6 and 'XXXX:XXXX' in masked_host:
            result = f"{parts.scheme}://{netloc}{parts.path}"
            if parts.query:
                result += f"?{parts.query}"
            if parts.fragment:
                result += f"#{parts.fragment}"
            return result

        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))

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

    def _redact_fqdns_safe(self, text: str) -> str:
        """Redact FQDNs with ReDoS protection via length pre-filtering"""
        def fqdn_mask_safe(match):
            domain = match.group(0)
            # Pre-filter: Skip obviously too-long domains
            if len(domain) > self.MAX_FQDN_LENGTH:
                return domain  # Don't process suspiciously long "domains"

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

            # Redact remaining bare FQDNs with ReDoS protection
            result = self._redact_fqdns_safe(result)

            # Restore IPv4 mask and Cisco MAC format
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

    def _should_redact_completely(self, tag: str, element: ET.Element, redact_ips: bool, redact_domains: bool) -> bool:
        """Check if element should be completely redacted and handle it. Returns True if handled."""
        if tag not in self.redact_elements:
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

    def _handle_key_element(self, tag: str, element: ET.Element, redact_ips: bool, redact_domains: bool) -> bool:
        """Handle <key> element specially - can be short secret or PEM blob. Returns True if handled."""
        if tag != 'key' or not element.text:
            return False

        text = element.text.strip()
        # Check if it's a PEM blob or long base64-like content
        # Uses class constants for length thresholds
        is_pem_or_blob = (
            self.PEM_MARKER.search(text) or
            len(text) >= self.KEY_BLOB_MIN_LENGTH or
            (len(text) > self.KEY_SHORT_THRESHOLD and
             text.replace('\n', '').replace('\r', '').replace(' ', '').isalnum())
        )

        if is_pem_or_blob:
            self._redact_text_and_track(element, 'Cert/Key', '[REDACTED_CERT_OR_KEY]')
        else:
            # Short key - treat as secret
            self._redact_text_and_track(element, 'Secret')

        # Process children
        for child in element:
            self.redact_element(child, redact_ips, redact_domains)

        return True

    def _handle_cert_key_element(self, tag: str, element: ET.Element) -> bool:
        """Handle certificate/key elements. Returns True if this is a cert/key element."""
        if tag not in self.cert_key_elements:
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

    def _apply_aggressive_redaction(
        self, element: ET.Element, text_already_processed: bool, redact_ips: bool, redact_domains: bool
    ) -> None:
        """Apply aggressive mode redaction to text and attributes"""
        if self._normalise_tag(element.tag) in self.redact_elements:
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

        # Handle complete redaction cases
        if self._should_redact_completely(tag, element, redact_ips, redact_domains):
            return

        # Handle special cases
        if self._handle_key_element(tag, element, redact_ips, redact_domains):
            return

        # Handle cert/key elements (don't return - continue to process children)
        self._handle_cert_key_element(tag, element)

        # Track whether we already processed text to avoid double processing in aggressive mode
        text_already_processed = self._redact_ip_containing_element(
            tag, tag_base, element, redact_ips, redact_domains
        )

        # Redact attributes with sensitive names
        self._redact_sensitive_attributes(element)

        # Recursively process child elements
        for child in element:
            self.redact_element(child, redact_ips, redact_domains)

        # Aggressive mode: apply redaction to text content, tail, and attributes
        if self.aggressive:
            self._apply_aggressive_redaction(element, text_already_processed, redact_ips, redact_domains)

    def _add_redaction_comment(self, root: ET.Element) -> None:
        """Add a comment to the XML indicating it was redacted"""
        # Import version from package
        # Handle circular import gracefully - version may not be available during module init
        try:
            from . import __version__  # pylint: disable=import-outside-toplevel,cyclic-import
            version = __version__
        except (ImportError, AttributeError):
            # Fallback: try to get version from pyproject.toml or use unknown
            try:
                # pylint: disable=import-outside-toplevel,reimported,redefined-outer-name
                pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
                if pyproject_path.exists():
                    content = pyproject_path.read_text(encoding='utf-8')
                    match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                    version = match.group(1) if match else "unknown"
                else:
                    version = "unknown"
            except Exception:  # pylint: disable=broad-except
                version = "unknown"

        comment_text = f" Redacted using pfsense-redactor v{version} "
        comment = ET.Comment(comment_text)

        # Insert comment as first child of root
        root.insert(0, comment)

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

            # G) Sanity check: ensure this is a pfSense config (namespace-robust)
            root_tag = root.tag.rsplit('}', 1)[-1].lower()
            if root_tag != 'pfsense':
                msg = f"[!] Warning: Root tag is '{root.tag}', expected 'pfsense'."
                if self.fail_on_warn:
                    self.logger.error("%s Exiting.", msg)
                    return False
                self.logger.warning("%s Proceeding anyway...", msg)

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

            # Write redacted configuration
            if stdout_mode:
                tree.write(sys.stdout.buffer, encoding='utf-8', xml_declaration=True)
            elif inplace:
                tree.write(input_file, encoding='utf-8', xml_declaration=True)
                self.logger.info("[+] Redacted configuration written in-place to: %s", input_file)
            else:
                tree.write(output_file, encoding='utf-8', xml_declaration=True)
                self.logger.info("[+] Redacted configuration written to: %s", output_file)

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
        if self.stats['secrets_redacted']:
            self.logger.info("    - Passwords/keys/secrets: %d", self.stats['secrets_redacted'])
        if self.stats['certs_redacted']:
            self.logger.info("    - Certificates: %d", self.stats['certs_redacted'])
        if self.stats['ips_redacted']:
            self.logger.info("    - IP addresses: %d", self.stats['ips_redacted'])
        if self.stats['macs_redacted']:
            self.logger.info("    - MAC addresses: %d", self.stats['macs_redacted'])
        if self.stats['domains_redacted']:
            self.logger.info("    - Domain names: %d", self.stats['domains_redacted'])
        if self.stats['emails_redacted']:
            self.logger.info("    - Email addresses: %d", self.stats['emails_redacted'])
        if self.stats['urls_redacted']:
            self.logger.info("    - URLs: %d", self.stats['urls_redacted'])

        if self.anonymise:
            self.logger.info("")
            self.logger.info("[+] Anonymisation stats:")
            self.logger.info("    - Unique IPs anonymised: %d", len(self.ip_aliases))
            self.logger.info("    - Unique domains anonymised: %d", len(self.domain_aliases))

        # Print samples if in dry-run-verbose mode
        if self.dry_run_verbose:
            self.logger.info("")
            self.logger.info("[+] Samples of changes (limit N=%d):", self.sample_limit)
            has_any = any(self.samples.get(cat) for cat in ['IP', 'URL', 'FQDN', 'MAC', 'Secret', 'Cert/Key'])
            if has_any:
                # Print in consistent order
                for category in ['IP', 'URL', 'FQDN', 'MAC', 'Secret', 'Cert/Key']:
                    if category in self.samples and self.samples[category]:
                        for before_masked, after in self.samples[category]:
                            self.logger.info("    %s: %s -> %s", category, before_masked, after)
            else:
                self.logger.info("    (no examples collected)")


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
    ips = set()
    networks = []
    domains = set()

    try:
        with open(filepath, 'r', encoding='utf-8') as file_handle:
            for _, line in enumerate(file_handle, 1):
                line = line.strip()
                # Skip blank lines and comments
                if not line or line.startswith('#'):
                    continue

                # Try to parse as IP address first
                try:
                    ipaddress.ip_address(line)
                    ips.add(line)
                    continue
                except ValueError:
                    pass

                # Try to parse as CIDR network
                try:
                    network = ipaddress.ip_network(line, strict=False)
                    networks.append(network)
                    continue
                except ValueError:
                    pass

                # Not an IP or CIDR, treat as domain (case-insensitive)
                domains.add(line.lower())

    except FileNotFoundError:
        if not silent_if_missing:
            logger = logging.getLogger('pfsense_redactor')
            logger.error("[!] Error: Allow-list file '%s' not found", filepath)
            sys.exit(1)
        # Silent if missing for default files
        return set(), [], set()
    except (IOError, OSError) as e:
        logger = logging.getLogger('pfsense_redactor')
        logger.error("[!] Error reading allow-list file: %s", e)
        sys.exit(1)
    except (ValueError, UnicodeDecodeError) as e:
        logger = logging.getLogger('pfsense_redactor')
        logger.error("[!] Error parsing allow-list file: %s", e)
        sys.exit(1)

    return ips, networks, domains


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


def main() -> None:
    """Main entry point for the pfSense redactor CLI"""
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

    parser.add_argument('input', help='Input pfSense config.xml file')
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
                        help='Redact usernames in URLs (e.g., ftp://user@host becomes ftp://REDACTED@host). By default, usernames are preserved while passwords are always redacted.')

    args = parser.parse_args()

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

    # Check if input file exists
    if not Path(args.input).exists():
        logger.error("[!] Error: Input file '%s' not found", args.input)
        sys.exit(1)

    # Check if input file is empty
    if Path(args.input).stat().st_size == 0:
        logger.error("[!] Error: Input file is empty")
        sys.exit(1)

    # Check if output file exists (unless force or special modes)
    if args.output and not args.force and not args.dry_run:
        if Path(args.output).exists():
            logger.error("[!] Error: Output file '%s' already exists. Use --force to overwrite.", args.output)
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
        redact_url_usernames=args.redact_url_usernames
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
