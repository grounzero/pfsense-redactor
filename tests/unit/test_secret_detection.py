"""Secret detection behaviour tests

Covers the v1.1.0 secret-detection work: pattern-based element matching,
free-text blob scanning, URL path and query secrets, high-entropy blob
screening, and --redact-descriptions.

Split out of test_focused_behaviour.py, which pylint caps at 1000 lines --
.pylintrc-tests deliberately leaves C0302 enabled for test modules, unlike
.pylintrc which disables it for the single-module production design.

Fixtures (basic_redactor, aggressive_redactor, redactor_factory) come from
tests/conftest.py.
"""
import xml.etree.ElementTree as ET

import pytest


# Element names that leaked before pattern-based tag matching was added.
# Every one is a real pfSense or package element name.
LEAKING_SECRET_ELEMENTS = [
    'rocommunity', 'rwcommunity',        # SNMP community strings
    'passphrase',                        # WPA/WPA2 PSK
    'auth_pass',                         # OpenVPN client password
    'presharedkey',                      # WireGuard peer PSK
    'ipsecpsk',                          # Per-user IPsec PSK
    'eap_password',                      # IPsec EAP credential
    'radiussecret',                      # Captive Portal RADIUS secret
    'authorizedkeys',                    # SSH authorized keys
    'accountkey',                        # ACME account key
    'dns_cf_token',                      # Cloudflare API token
    'maxmind_key',                       # pfBlockerNG MaxMind licence key
    'influx_token',                      # Telegraf InfluxDB token
    'token',                             # Bare token
    'access_key', 'secret_access_key',   # S3 credentials
    'tlspskvalue',                       # Zabbix agent PSK
    'userkey',                           # Pushover user key
    'bearer_token',
]

# Element names that match the secret pattern but are not secrets
NON_SECRET_ELEMENTS = [
    'snortcommunityrules',   # Boolean "use community ruleset" toggle
    'pass_order',            # Snort/Suricata rule ordering
    'password_type',         # Hashing scheme indicator
    'source_hash_key',       # HAProxy algorithm selector
    'certref',               # Certificate reference, not key material
    'keylen',
    'sshdkeyonly',
]


class TestSecretElementPatternMatching:
    """Secret detection must match real element names, not just exact entries"""

    @pytest.mark.parametrize('tag', LEAKING_SECRET_ELEMENTS)
    def test_secret_element_is_redacted(self, basic_redactor, tag):
        """Each previously-leaking element name is now redacted"""
        root = ET.fromstring(f'<pfsense><a><{tag}>CANARY</{tag}></a></pfsense>')
        basic_redactor.redact_element(root)

        assert 'CANARY' not in ET.tostring(root, encoding='unicode')

    @pytest.mark.parametrize('tag', NON_SECRET_ELEMENTS)
    def test_non_secret_element_is_preserved(self, basic_redactor, tag):
        """Deny-listed and non-matching elements keep their values"""
        root = ET.fromstring(f'<pfsense><a><{tag}>plainvalue</{tag}></a></pfsense>')
        basic_redactor.redact_element(root)

        assert 'plainvalue' in ET.tostring(root, encoding='unicode')

    def test_numbered_variant_is_redacted(self, basic_redactor):
        """tag_base must be applied to secret matching, not just IP elements"""
        root = ET.fromstring(
            '<pfsense><a><password>A</password><password2>B</password2>'
            '<passwordagain>C</passwordagain></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert '>A<' not in output
        assert '>B<' not in output
        assert '>C<' not in output

    def test_short_cert_reference_is_preserved(self, basic_redactor):
        """Cert-ish tags holding short reference IDs stay readable"""
        root = ET.fromstring('<pfsense><a><ssl_ca_cert>5f3a1c9b</ssl_ca_cert></a></pfsense>')
        basic_redactor.redact_element(root)

        assert '5f3a1c9b' in ET.tostring(root, encoding='unicode')

    def test_cert_element_with_pem_is_redacted(self, basic_redactor):
        """The same tag holding actual PEM material is redacted"""
        pem = (
            '-----BEGIN CERTIFICATE-----\n'
            'MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKKzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n'
            '-----END CERTIFICATE-----'
        )
        root = ET.fromstring(f'<pfsense><a><ha_certificates>{pem}</ha_certificates></a></pfsense>')
        basic_redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert 'BEGIN CERTIFICATE' not in output
        assert '[REDACTED_CERT_OR_KEY]' in output

    def test_key_element_keeps_cert_distinction(self, basic_redactor):
        """<key> retains its PEM-vs-short-secret handling"""
        pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAu1SU1LfVLPHCoz\n-----END RSA PRIVATE KEY-----'
        root = ET.fromstring(f'<pfsense><key>{pem}</key></pfsense>')
        basic_redactor.redact_element(root)

        assert '[REDACTED_CERT_OR_KEY]' in ET.tostring(root, encoding='unicode')


class TestBlobTextElements:
    """Opaque free-text containers are scanned for inline credentials"""

    def test_custom_options_askpass_directive(self, basic_redactor):
        """askpass argument is redacted in OpenVPN custom_options"""
        root = ET.fromstring(
            '<pfsense><a><custom_options>askpass /secret/passfile</custom_options></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        assert '/secret/passfile' not in ET.tostring(root, encoding='unicode')

    def test_upsd_users_inline_password(self, basic_redactor):
        """key=value is found mid-line, not only at line start"""
        root = ET.fromstring(
            '<pfsense><a><upsd_users>[admin] password=hunter2</upsd_users></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert 'hunter2' not in output
        assert '[admin]' in output, 'non-secret content should survive'

    def test_non_secret_directive_preserved(self, basic_redactor):
        """Ordinary directives in blob text are left alone"""
        root = ET.fromstring(
            '<pfsense><a><custom_options>verb 3\nkeepalive 10 60</custom_options></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert 'verb 3' in output
        assert 'keepalive 10 60' in output

    def test_url_secrets_scanned_in_blob_elements(self, basic_redactor):
        """Blob elements must not get less URL scanning than unknown elements"""
        url = 'https://feeds.corp.example/list?token=FEEDTOKEN9999'
        root = ET.fromstring(
            f'<pfsense><a><detail>synced from {url}</detail>'
            f'<otherfield>synced from {url}</otherfield></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        blob_text = root.find('.//detail').text
        assert 'FEEDTOKEN9999' not in blob_text
        assert blob_text == root.find('.//otherfield').text, 'parity with unknown element'

    def test_url_in_blob_not_corrupted_by_kv_scanner(self, basic_redactor):
        """The KV scan must not re-process an already-redacted URL"""
        root = ET.fromstring(
            '<pfsense><a><custom_options>'
            'remote https://x.example/u?token=ABC123'
            '</custom_options></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        text = root.find('.//custom_options').text

        assert 'ABC123' not in text
        assert '%5D]' not in text, 'double-encoded marker left a stray bracket'

    def test_kv_and_url_scanning_coexist(self, basic_redactor):
        """Directives, key=value pairs and URLs are all handled in one blob"""
        root = ET.fromstring(
            '<pfsense><a><custom_options>askpass /secret/pf\n'
            'password=hunter2\n'
            'remote https://x.example/u?token=ABC123\n'
            'verb 3</custom_options></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        text = root.find('.//custom_options').text

        assert '/secret/pf' not in text
        assert 'hunter2' not in text
        assert 'ABC123' not in text
        assert 'verb 3' in text, 'non-secret directives must survive'

    def test_aggressive_redacts_blob_wholesale(self, aggressive_redactor):
        """Aggressive mode does not rely on recognising the inner format"""
        root = ET.fromstring(
            '<pfsense><a><userparams>UserParameter=x,cat /root/creds</userparams></a></pfsense>'
        )
        aggressive_redactor.redact_element(root)

        assert '/root/creds' not in ET.tostring(root, encoding='unicode')


class TestURLSecretRedaction:
    """Credentials in URL paths and query strings"""

    def test_secret_query_param_redacted(self, basic_redactor):
        """Anonymising the host is not enough if the token survives"""
        result = basic_redactor.redact_text(
            'https://api.dnsprov.example/update?token=s3cr3tvalue&host=fw'
        )

        assert 's3cr3tvalue' not in result
        assert 'REDACTED' in result

    def test_non_secret_query_param_preserved(self, basic_redactor):
        """Ordinary query parameters keep their values"""
        result = basic_redactor.redact_text('https://feeds.example.net/list.txt?format=csv')

        assert 'format=csv' in result

    def test_url_in_unrecognised_element_is_scanned(self, basic_redactor):
        """URLs are found by content, not only in known URL-bearing tags"""
        root = ET.fromstring(
            '<pfsense><a><updateurl>https://api.example.com/u?token=leakme</updateurl></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        assert 'leakme' not in ET.tostring(root, encoding='unicode')

    def test_webhook_path_token_redacted_aggressive(self, aggressive_redactor):
        """Webhook secrets live in the path, not the query string

        Uses a .example host rather than the real webhook provider's domain:
        the redaction under test operates on path segments only, and a
        realistic provider hostname makes the fixture match secret-scanning
        patterns and blocks pushes.
        """
        result = aggressive_redactor.redact_text(
            'https://hooks.chat-provider.example/services/T00000000/B00000000/XiFdb92Kd8sM1nRq7vLwP3zY'
        )

        assert 'XiFdb92Kd8sM1nRq7vLwP3zY' not in result

    def test_userinfo_redacted_in_unrecognised_element(self, basic_redactor):
        """A URL's password must not survive beside a [REDACTED] query marker

        Emitting a partially-redacted URL reads as sanitised when it is not.
        """
        root = ET.fromstring(
            '<pfsense><a><updateurl>'
            'https://ddnsuser:Sup3rS3cret1@members.dyndns.example/nic/update?password=TOKEN'
            '</updateurl></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert 'Sup3rS3cret1' not in output
        assert 'TOKEN' not in output

    def test_userinfo_redacted_without_query_secret(self, basic_redactor):
        """Credentials are redacted even when nothing else in the URL changes"""
        root = ET.fromstring(
            '<pfsense><a><backupurl>'
            'ftp://backupsvc:BackupPw99@backup.corp.example/nightly'
            '</backupurl></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        assert 'BackupPw99' not in ET.tostring(root, encoding='unicode')

    def test_userinfo_parity_with_known_url_element(self, basic_redactor):
        """Known and unknown URL carriers must redact credentials alike"""
        url = 'https://myuser:Sup3rS3cret1@host.example/nic/update?password=TOKEN'
        root = ET.fromstring(
            f'<pfsense><a><url>{url}</url><updateurl>{url}</updateurl></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        for tag in ('url', 'updateurl'):
            assert 'Sup3rS3cret1' not in root.find('.//' + tag).text

    def test_masked_host_still_redacts_query_and_userinfo(self, basic_redactor):
        """An already-masked host does not imply the rest of the URL is safe"""
        result = basic_redactor.redact_text(
            'https://user:pw@example.com/nic/update?password=SECRET'
        )

        assert 'SECRET' not in result
        assert ':pw@' not in result

    def test_short_path_segments_preserved(self, aggressive_redactor):
        """Ordinary route names are not mistaken for tokens"""
        result = aggressive_redactor.redact_text('https://feeds.example.net/lists/blocklist')

        assert '/lists/blocklist' in result
        assert 'REDACTED' not in result


class TestHighEntropyBlobs:
    """Unrecognised high-entropy values are reported, and redacted when asked"""

    BLOB_XML = (
        '<pfsense><installedpackages><mycustompkg><config>'
        '<blob>Q0FOQVJZX0JBU0U2NEJMT0JfQ0FOQVJZX0JBU0U2NEJMT0JfQ0FOQVJZ</blob>'
        '</config></mycustompkg></installedpackages></pfsense>'
    )

    def test_retained_by_default_but_reported(self, basic_redactor):
        """Default mode keeps the value but records where it is"""
        root = ET.fromstring(self.BLOB_XML)
        basic_redactor.redact_element(root)

        assert basic_redactor.stats['high_entropy_retained'] == 1
        assert any('blob' in p for p in basic_redactor.high_entropy_paths)
        assert 'Q0FOQVJZ' in ET.tostring(root, encoding='unicode')

    def test_reported_path_is_fully_qualified(self, basic_redactor):
        """The reported path locates the element for manual review"""
        root = ET.fromstring(self.BLOB_XML)
        basic_redactor.redact_element(root)

        assert 'pfsense/installedpackages/mycustompkg/config/blob' in basic_redactor.high_entropy_paths

    def test_redacted_under_aggressive(self, aggressive_redactor):
        """Aggressive mode redacts unrecognised blobs"""
        root = ET.fromstring(self.BLOB_XML)
        aggressive_redactor.redact_element(root)

        assert 'Q0FOQVJZ' not in ET.tostring(root, encoding='unicode')

    def test_ordinary_text_not_flagged(self, basic_redactor):
        """Long prose is not mistaken for encoded key material"""
        root = ET.fromstring(
            '<pfsense><a><notes>This is a fairly long human readable note about the setup</notes></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        assert basic_redactor.stats['high_entropy_retained'] == 0


class TestRedactDescriptions:
    """--redact-descriptions covers personal names in free-text fields"""

    DESCR_XML = (
        '<pfsense><dhcpd><lan><staticmap>'
        '<hostname>ceo-laptop</hostname>'
        '<descr>CEO Jane Doe personal MBP</descr>'
        '</staticmap></lan></dhcpd></pfsense>'
    )

    def test_descriptions_preserved_by_default(self, basic_redactor):
        """Descriptions aid troubleshooting, so they stay unless asked"""
        root = ET.fromstring(self.DESCR_XML)
        basic_redactor.redact_element(root)

        assert 'Jane Doe' in ET.tostring(root, encoding='unicode')

    def test_descriptions_redacted_when_enabled(self, redactor_factory):
        """The flag removes descriptions and identifiers"""
        redactor = redactor_factory(redact_descriptions=True)
        root = ET.fromstring(self.DESCR_XML)
        redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert 'Jane Doe' not in output
        assert 'ceo-laptop' not in output

    def test_ssid_redacted_when_enabled(self, redactor_factory):
        """SSIDs are organisation-identifying"""
        redactor = redactor_factory(redact_descriptions=True)
        root = ET.fromstring('<pfsense><a><ssid>ACME-Corp-WiFi</ssid></a></pfsense>')
        redactor.redact_element(root)

        assert 'ACME-Corp-WiFi' not in ET.tostring(root, encoding='unicode')


class TestURLPathCredentialFormats:
    """Credential formats embedded in URL path segments

    The boundaries in _is_secretish_path_segment are load-bearing; each case
    here corresponds to a format that slipped through in 1.1.0.
    """

    @pytest.mark.parametrize('segment,description', [
        ('AKIAIOSFODNN7EXAMPLE', 'AWS access key ID - exactly 20 chars'),
        ('bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw', 'Telegram bot token - contains a colon'),
        ('XXXXXXXXXXXXXXXXXXXXXXXX', '24-char token with no digit'),
        ('4nBv8kQ2rT9wZxL6mYpJ7dCf', 'Slack webhook token'),
        ('aB3dE5gH7jK9lM1nO3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hI3jK5lM7nO9pQ1rS3t', 'Discord webhook token'),
    ])
    def test_credential_segment_detected(self, segment, description):
        """Each format is recognised as a credential"""
        from pfsense_redactor.redactor import PfSenseRedactor

        assert PfSenseRedactor._is_secretish_path_segment(segment), description

    @pytest.mark.parametrize('segment,description', [
        ('Open_VM_Tools_package', 'route name the digit rule protects (21 chars)'),
        ('Setup_Snort_Package', 'route name, 19 chars'),
        ('services', 'short route'),
        ('webhooks', 'short route'),
        ('sendMessage', 'short route'),
        ('T024BE7LD', 'short identifier'),
    ])
    def test_route_name_not_flagged(self, segment, description):
        """Ordinary route names must not be mistaken for credentials"""
        from pfsense_redactor.redactor import PfSenseRedactor

        assert not PfSenseRedactor._is_secretish_path_segment(segment), description

    def test_aws_key_redacted_in_url(self, aggressive_redactor):
        """End to end: an AWS key ID in a path is redacted"""
        result = aggressive_redactor.redact_text('https://example.org/api/AKIAIOSFODNN7EXAMPLE/data')

        assert 'AKIAIOSFODNN7EXAMPLE' not in result

    def test_telegram_token_redacted_in_url(self, aggressive_redactor):
        """The colon must not shield the secret half of the token"""
        result = aggressive_redactor.redact_text(
            'https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage'
        )

        assert 'AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw' not in result
        assert 'sendMessage' in result, 'the route should survive'

    def test_webhook_element_redacted_whole(self, basic_redactor):
        """A webhook URL is a credential in its entirety, not just its last segment"""
        root = ET.fromstring(
            '<pfsense><a><webhook_url>'
            'https://hooks.example.com/services/T00/B00/SomeOpaqueTokenValue'
            '</webhook_url></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        assert 'SomeOpaqueTokenValue' not in ET.tostring(root, encoding='unicode')


class TestFilenamesNotTreatedAsDomains:
    """FQDN substitution must not rewrite filenames and paths

    Rewriting 'haproxy.sh' to 'example.com' corrupts the output rather than
    redacting it, and pfBlockerNG feed names and cron commands are exactly what
    people share a config to get help with.
    """

    @pytest.mark.parametrize('text', [
        'https://feeds.example.net/lists/emerging-block.rules',
        'https://updates.example.org/pfblocker/list.txt',
    ])
    def test_filename_in_url_path_preserved(self, basic_redactor, text):
        """The host is masked; the filename in the path is not"""
        result = basic_redactor.redact_text(text)

        assert 'example.com' in result, 'host should still be masked'
        assert result.rsplit('/', 1)[-1] == text.rsplit('/', 1)[-1], 'filename should survive'

    @pytest.mark.parametrize('text', [
        '/usr/local/etc/rc.d/haproxy.sh restart',
        '/usr/local/etc/snort/snort.conf',
        'backup-2026.tar.gz',
        'config.xml',
    ])
    def test_filesystem_path_preserved(self, aggressive_redactor, text):
        """Bare paths and filenames are left alone even under --aggressive"""
        assert aggressive_redactor.redact_text(text) == text

    @pytest.mark.parametrize('domain', [
        'host.internal.corp.example',
        'mail.acme-corp.example',
        'fw.corp.local',
    ])
    def test_real_domains_still_redacted(self, basic_redactor, domain):
        """The filename rules must not weaken domain redaction"""
        result = basic_redactor.redact_text(domain)

        assert domain not in result
        assert 'example.com' in result

    def test_ambiguous_extension_redacted_outside_path_context(self, basic_redactor):
        """'.sh' is a real TLD, so it is only preserved in path context"""
        assert basic_redactor.redact_text('/etc/rc.d/haproxy.sh') == '/etc/rc.d/haproxy.sh'
        assert 'haproxy.sh' not in basic_redactor.redact_text('visit haproxy.sh for details')
