"""
Tests for anchored sensitive attribute matching to prevent false positives.

This test suite verifies that the sensitive attribute pattern uses word boundaries
to avoid matching substrings like 'pass' in 'compass_heading' or 'auth' in 'author'.
"""
import xml.etree.ElementTree as ET
from pfsense_redactor.redactor import PfSenseRedactor


class TestSensitiveAttributeAnchoring:
    """Test that sensitive attribute matching uses anchored patterns"""

    def test_compass_heading_not_redacted(self):
        """Verify 'compass_heading' attribute is not redacted (contains 'pass' substring)"""
        xml = '<config><device compass_heading="north"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        # compass_heading should NOT be redacted (doesn't match \bpass\b)
        assert root.find('device').get('compass_heading') == 'north'
        assert redactor.stats['secrets_redacted'] == 0

    def test_author_not_redacted(self):
        """Verify 'author' attribute is not redacted (contains 'auth' substring)"""
        xml = '<config><document author="John Doe"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        # author should NOT be redacted (doesn't match \bauth\b or \bauthentication\b)
        assert root.find('document').get('author') == 'John Doe'
        assert redactor.stats['secrets_redacted'] == 0

    def test_bypass_not_redacted(self):
        """Verify 'bypass' attribute is not redacted (contains 'pass' substring)"""
        xml = '<config><rule bypass="true"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        # bypass should NOT be redacted
        assert root.find('rule').get('bypass') == 'true'
        assert redactor.stats['secrets_redacted'] == 0

    def test_password_is_redacted(self):
        """Verify 'password' attribute IS redacted (exact match)"""
        xml = '<config><user password="secret123"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        # password SHOULD be redacted
        assert root.find('user').get('password') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 1

    def test_passwd_is_redacted(self):
        """Verify 'passwd' attribute IS redacted"""
        xml = '<config><user passwd="secret123"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        assert root.find('user').get('passwd') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 1

    def test_pass_is_redacted(self):
        """Verify 'pass' attribute IS redacted (whole word)"""
        xml = '<config><user pass="secret123"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        assert root.find('user').get('pass') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 1

    def test_api_key_variants_redacted(self):
        """Verify api_key, api-key, and apikey are all redacted"""
        xml = '''<config>
            <service api_key="key1" api-key="key2" apikey="key3"/>
        </config>'''
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        service = root.find('service')
        assert service.get('api_key') == '[REDACTED]'
        assert service.get('api-key') == '[REDACTED]'
        assert service.get('apikey') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 3

    def test_auth_variants_redacted(self):
        """Verify auth, auth_key, auth_token, authentication are redacted"""
        xml = '''<config>
            <service auth="val1" auth_key="val2" auth_token="val3" authentication="val4"/>
        </config>'''
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        service = root.find('service')
        assert service.get('auth') == '[REDACTED]'
        assert service.get('auth_key') == '[REDACTED]'
        assert service.get('auth_token') == '[REDACTED]'
        assert service.get('authentication') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 4

    def test_client_secret_variants_redacted(self):
        """Verify client_secret and client-secret are redacted"""
        xml = '<config><oauth client_secret="s1" client-secret="s2"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        oauth = root.find('oauth')
        assert oauth.get('client_secret') == '[REDACTED]'
        assert oauth.get('client-secret') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 2

    def test_mixed_safe_and_sensitive_attributes(self):
        """Verify only sensitive attributes are redacted in mixed scenarios"""
        xml = '''<config>
            <device 
                compass_heading="north" 
                password="secret" 
                author="John" 
                api_key="key123"
                bypass="true"
                token="abc"
            />
        </config>'''
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        device = root.find('device')
        # Safe attributes preserved
        assert device.get('compass_heading') == 'north'
        assert device.get('author') == 'John'
        assert device.get('bypass') == 'true'

        # Sensitive attributes redacted
        assert device.get('password') == '[REDACTED]'
        assert device.get('api_key') == '[REDACTED]'
        assert device.get('token') == '[REDACTED]'

        # Should have redacted exactly 3 attributes
        assert redactor.stats['secrets_redacted'] == 3

    def test_case_insensitive_matching(self):
        """Verify pattern matching is case-insensitive"""
        xml = '''<config>
            <service PASSWORD="s1" ApiKey="s2" AUTH="s3"/>
        </config>'''
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        service = root.find('service')
        assert service.get('PASSWORD') == '[REDACTED]'
        assert service.get('ApiKey') == '[REDACTED]'
        assert service.get('AUTH') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 3

    def test_key_attribute_redacted(self):
        """Verify 'key' attribute is redacted"""
        xml = '<config><item key="secret"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        assert root.find('item').get('key') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 1

    def test_secret_attribute_redacted(self):
        """Verify 'secret' attribute is redacted"""
        xml = '<config><item secret="value"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        assert root.find('item').get('secret') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 1

    def test_bearer_token_redacted(self):
        """Verify 'bearer' and 'token' attributes are redacted"""
        xml = '<config><auth bearer="xyz" token="abc"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        auth = root.find('auth')
        assert auth.get('bearer') == '[REDACTED]'
        assert auth.get('token') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 2

    def test_cookie_attribute_redacted(self):
        """Verify 'cookie' attribute is redacted"""
        xml = '<config><session cookie="sessionid=xyz"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        assert root.find('session').get('cookie') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 1

    def test_signature_attribute_redacted(self):
        """Verify 'signature' attribute is redacted"""
        xml = '<config><message signature="abc123"/></config>'
        root = ET.fromstring(xml)

        redactor = PfSenseRedactor()
        redactor.redact_element(root)

        assert root.find('message').get('signature') == '[REDACTED]'
        assert redactor.stats['secrets_redacted'] == 1


class TestDescriptionAttributes:
    """Free-prose attributes, redacted only under --redact-descriptions

    SENSITIVE_ATTR_PATTERN catches attributes *named* for a secret. These are
    the ones whose name says nothing about the contents - a note, a label - and
    where the value has to go wholesale because no pattern picks a PIN or a
    circuit reference out of a sentence.

    Opt-in for the same reason description elements are: notes are often the
    most useful part of a config to whoever is reading it.
    """

    NOTE_XML = '<config><config_note note="ISP pin 4815" secret="s3cret">x</config_note></config>'

    def test_free_text_attribute_kept_by_default(self):
        """Default runs keep notes, which is what makes a config readable"""
        root = ET.fromstring(self.NOTE_XML)

        PfSenseRedactor().redact_element(root)

        assert root.find('config_note').get('note') == 'ISP pin 4815'

    def test_free_text_attribute_kept_under_aggressive_alone(self):
        """--aggressive is about identifiers, not about discarding prose"""
        root = ET.fromstring(self.NOTE_XML)

        PfSenseRedactor(aggressive=True).redact_element(root)

        assert root.find('config_note').get('note') == 'ISP pin 4815'

    def test_free_text_attribute_redacted_with_the_flag(self):
        """--redact-descriptions covers attributes as well as elements"""
        root = ET.fromstring(self.NOTE_XML)

        PfSenseRedactor(redact_descriptions=True).redact_element(root)

        assert root.find('config_note').get('note') == '[REDACTED]'

    def test_secret_named_attribute_redacted_regardless(self):
        """The existing name-based rule is unchanged by any of this"""
        root = ET.fromstring(self.NOTE_XML)

        PfSenseRedactor().redact_element(root)

        assert root.find('config_note').get('secret') == '[REDACTED]'

    def test_structural_attributes_survive_the_flag(self):
        """--redact-descriptions must not strip attributes that carry meaning

        Redacting a version or an interface name would break the reader's
        ability to follow the config, which is the thing this tool exists to
        preserve.
        """
        xml = '<config><rule version="1.0" interface="wan" type="pass"/></config>'
        root = ET.fromstring(xml)

        PfSenseRedactor(redact_descriptions=True).redact_element(root)

        rule = root.find('rule')
        assert rule.get('version') == '1.0'
        assert rule.get('interface') == 'wan'
        assert rule.get('type') == 'pass'

    def test_attribute_name_match_is_case_insensitive(self):
        """Configs are written by hand, and Note is as likely as note"""
        root = ET.fromstring('<config><x Note="private remark"/></config>')

        PfSenseRedactor(redact_descriptions=True).redact_element(root)

        assert root.find('x').get('Note') == '[REDACTED]'
