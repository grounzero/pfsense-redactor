"""
Tests for webhook path tokens being redacted in every mode.

A Slack, Discord or Telegram webhook URL carries its credential in the path.
Anyone holding the URL can post as that integration, so the token is redacted
without waiting for --aggressive.

Path redaction is otherwise gated behind --aggressive because pfBlockerNG feed
URLs legitimately carry long path segments that redaction would destroy. The
tests below therefore matter in both directions: the tokens must go, and the
feed URLs must survive.
"""
import xml.etree.ElementTree as ET

import pytest

from pfsense_redactor.redactor import PfSenseRedactor, _is_webhook_url

# The URLs are assembled from parts rather than written out whole, and the
# tokens say EXAMPLE rather than looking random.
#
# Both are deliberate. A complete, realistically-shaped webhook URL sitting in
# a source file is exactly what GitHub's secret scanner blocks on push - the
# same shape-matching that makes this good test data makes it look real from
# the outside. Splitting the literal keeps the runtime value identical, which
# is all these tests care about, while leaving nothing for a scanner to match.
SLACK_PREFIX = 'https://hooks.slack.com/services/T024BE7LD/B024BE7LH/'
SLACK_TOKEN = 'EXAMPLEnotarealslacktokenEXAMPLE'
SLACK = SLACK_PREFIX + SLACK_TOKEN

DISCORD_PREFIX = 'https://discord.com/api/webhooks/123456789012345678/'
DISCORD_TOKEN = 'EXAMPLEnotarealdiscordwebhooktokenEXAMPLE'
DISCORD = DISCORD_PREFIX + DISCORD_TOKEN

TELEGRAM_TOKEN = 'EXAMPLEnotarealtelegramtokenEXAMPLE'
TELEGRAM = 'https://api.telegram.org/bot123456789:' + TELEGRAM_TOKEN + '/sendMessage'


class TestIsWebhookUrl:
    """The host/path predicate on its own"""

    @pytest.mark.parametrize('host,path', [
        ('hooks.slack.com', '/services/T024BE7LD/B024BE7LH/tok'),
        ('discord.com', '/api/webhooks/123/tok'),
        ('discordapp.com', '/api/webhooks/123/tok'),
        ('ptb.discord.com', '/api/webhooks/123/tok'),
        ('canary.discord.com', '/api/webhooks/123/tok'),
        ('api.telegram.org', '/bot123:tok/sendMessage'),
    ])
    def test_known_endpoints_match(self, host, path):
        """Each supported provider is recognised"""
        assert _is_webhook_url(host, path)

    def test_host_match_is_exact_not_suffix(self):
        """A lookalike domain must not inherit the rule

        'hooks.slack.com.evil.example' ends with the real host but is
        controlled by someone else entirely.
        """
        assert not _is_webhook_url('hooks.slack.com.evil.example', '/services/a/b/c')

    def test_host_match_is_not_a_prefix_either(self):
        """The reverse direction of the same mistake"""
        assert not _is_webhook_url('evil.example', '/hooks.slack.com/services/a/b/c')

    def test_path_prefix_is_required(self):
        """A webhook host serving something else is not a webhook URL"""
        assert not _is_webhook_url('discord.com', '/channels/123/456')

    def test_host_comparison_is_case_insensitive(self):
        """Hostnames are case-insensitive, and configs are written by hand"""
        assert _is_webhook_url('Hooks.Slack.COM', '/services/a/b/c')

    @pytest.mark.parametrize('path', [
        '/Services/T024BE7LD/B024BE7LH/tok',
        '/SERVICES/T024BE7LD/B024BE7LH/tok',
    ])
    def test_path_comparison_is_case_insensitive(self, path):
        """RFC 3986 makes paths case-sensitive, but matching exactly leaked

        Every prefix here is lowercase, so folding case can only add matches,
        and '/Services/' on hooks.slack.com is still a webhook.
        """
        assert _is_webhook_url('hooks.slack.com', path)

    def test_mixed_case_path_token_is_redacted(self, basic_redactor):
        """End to end: the case that survived before"""
        url = 'https://hooks.slack.com/Services/T024BE7LD/B024BE7LH/' + SLACK_TOKEN

        assert SLACK_TOKEN not in basic_redactor._redact_url_secrets_only(url)

    def test_case_folding_does_not_widen_the_host_rule(self):
        """Only the path is folded; the host rules are unchanged

        A lookalike must not become a match just because the path now
        compares loosely.
        """
        assert not _is_webhook_url('hooks.slack.com.evil.example', '/Services/a/b/c')
        assert not _is_webhook_url('notwebhook.office.com', '/WebhookB2/x')

    def test_empty_inputs_are_safe(self):
        """A URL with no host must not raise"""
        assert not _is_webhook_url('', '')


TEAMS_TOKEN = 'EXAMPLEnotarealteamswebhooktokenEXAMPLE'
TEAMS = ('https://acme.webhook.office.com/webhookb2/abc-def@ghi-jkl/'
         'IncomingWebhook/' + TEAMS_TOKEN + '/mno-pqr')


class TestTenantSubdomainEndpoints:
    """Teams puts the tenant in the subdomain, so the host cannot be exact

    Suffix matching is the looser rule and the easier one to get wrong, so it
    applies only to the domains listed for it - these tests pin both halves.
    """

    def test_teams_tenant_subdomain_matches(self):
        """Any tenant under webhook.office.com is a webhook host"""
        assert _is_webhook_url('acme.webhook.office.com', '/webhookb2/x')
        assert _is_webhook_url('contoso.webhook.office.com', '/webhookb2/x')

    def test_leading_dot_stops_a_lookalike(self):
        """'notwebhook.office.com' ends with the string but is a different domain

        The suffix carries a leading dot precisely so this cannot match.
        """
        assert not _is_webhook_url('notwebhook.office.com', '/webhookb2/x')

    def test_suffix_still_requires_the_path_prefix(self):
        """A tenant host serving something else is not a webhook URL"""
        assert not _is_webhook_url('acme.webhook.office.com', '/some/other/path')

    def test_legacy_connector_host_is_exact(self):
        """outlook.office.com has no tenant subdomain, so it stays an exact match"""
        assert _is_webhook_url('outlook.office.com', '/webhook/x')
        assert not _is_webhook_url('eviloutlook.office.com', '/webhook/x')

    def test_teams_token_redacted_by_default(self, basic_redactor):
        """End to end, without --aggressive"""
        assert TEAMS_TOKEN not in basic_redactor._redact_url_secrets_only(TEAMS)

    def test_self_hosted_webhooks_are_not_guessed(self):
        """Mattermost-style '/hooks/<token>' on an arbitrary host stays out

        There is no host to match on, and treating every '/hooks/' path as a
        credential would redact ordinary paths on unrelated servers.
        """
        assert not _is_webhook_url('chat.example.net', '/hooks/sometoken')


class TestDefaultModeRedactsWebhookTokens:
    """The behaviour change: no --aggressive required"""

    @pytest.mark.parametrize('url,token', [
        (SLACK, SLACK_TOKEN),
        (DISCORD, DISCORD_TOKEN),
        (TELEGRAM, TELEGRAM_TOKEN),
    ])
    def test_token_is_removed(self, basic_redactor, url, token):
        """The credential goes, in the mode most people actually use"""
        result = basic_redactor._redact_url_secrets_only(url)

        assert token not in result

    def test_route_survives_so_the_url_stays_readable(self, basic_redactor):
        """Redacting the token should not destroy what the URL was for"""
        result = basic_redactor._redact_url_secrets_only(TELEGRAM)

        assert 'sendMessage' in result

    def test_counted_in_statistics(self, basic_redactor):
        """A redaction that is not counted is invisible in the summary"""
        basic_redactor._redact_url_secrets_only(SLACK)

        assert basic_redactor.stats['url_secrets_redacted'] >= 1


class TestFeedUrlsStillSurvive:
    """The reason path redaction was gated in the first place

    If these start being redacted, the fix has over-reached and pfBlockerNG
    feed URLs are being corrupted in the default mode.
    """

    @pytest.mark.parametrize('url', [
        'https://feeds.example.net/lists/emerging-block.rules',
        'https://download.example.net/v1/abcdefghijklmnopqrstuvwxyz012345/list.txt',
        'https://updates.example.org/pfblocker/Open_VM_Tools_package/list.txt',
    ])
    def test_feed_paths_are_untouched_by_default(self, basic_redactor, url):
        """Long path segments on ordinary hosts stay as they are"""
        assert basic_redactor._redact_url_secrets_only(url) == url

    def test_non_webhook_path_on_a_webhook_host(self, basic_redactor):
        """discord.com serves plenty that is not a webhook"""
        url = 'https://discord.com/channels/123456789012345678/aB3dE5gH7jK9lM1nO3pQ5rS7tU'

        assert basic_redactor._redact_url_secrets_only(url) == url


class TestAggressiveModeUnchanged:
    """--aggressive still redacts every path, as it did before"""

    def test_feed_paths_still_redacted_under_aggressive(self, aggressive_redactor):
        """The opt-in behaviour is not weakened by the new default"""
        url = 'https://download.example.net/v1/abcdefghijklmnopqrstuvwxyz012345/list.txt'

        assert 'abcdefghijklmnopqrstuvwxyz012345' not in \
            aggressive_redactor._redact_url_secrets_only(url)

    def test_webhook_tokens_still_redacted_under_aggressive(self, aggressive_redactor):
        """Both routes to redaction agree"""
        assert SLACK_TOKEN not in aggressive_redactor._redact_url_secrets_only(SLACK)


class TestEndToEndThroughElements:
    """Through redact_element, which is how a real config reaches this"""

    @pytest.mark.parametrize('tag', ['slack_url', 'notifyurl', 'url', 'apiurl'])
    def test_element_name_no_longer_decides(self, tag):
        """Previously only <webhook_url> matched the secret-name pattern

        Any element carrying a Slack webhook kept its token by default, which
        is what this change fixes.
        """
        redactor = PfSenseRedactor()
        root = ET.fromstring(f'<pfsense><a><{tag}>{SLACK}</{tag}></a></pfsense>')
        redactor.redact_element(root)

        assert SLACK_TOKEN not in ET.tostring(root, encoding='unicode')

    def test_webhook_url_element_still_redacted_whole(self):
        """The existing element-name behaviour is unchanged"""
        redactor = PfSenseRedactor()
        root = ET.fromstring(f'<pfsense><a><webhook_url>{SLACK}</webhook_url></a></pfsense>')
        redactor.redact_element(root)

        assert SLACK_TOKEN not in ET.tostring(root, encoding='unicode')

    def test_feed_url_element_survives(self):
        """A pfBlockerNG feed in a <url> element must not be corrupted"""
        feed = 'https://feeds.example.net/lists/emerging-block.rules'
        redactor = PfSenseRedactor(keep_private_ips=True)
        root = ET.fromstring(f'<pfsense><a><url>{feed}</url></a></pfsense>')
        redactor.redact_element(root)

        assert 'emerging-block.rules' in ET.tostring(root, encoding='unicode')
