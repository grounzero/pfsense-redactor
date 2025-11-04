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
