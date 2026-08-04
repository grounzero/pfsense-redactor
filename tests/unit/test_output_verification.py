"""The independent verifier, and proof that it is actually independent

A verifier that only passes when the transformer is correct proves nothing. The
tests that matter here are the defect-injection ones: the transformer is broken
on purpose, one class of secret at a time, and the verifier has to notice
without being told what changed.

The rest pin the properties that make a finding safe to publish - metadata
only, never a value, never a prefix, never a hash - and the bounds that keep
the verifier from becoming the resource problem it exists to look for.

Every value here is synthetic.
"""
import xml.etree.ElementTree as ET

import pytest

from pfsense_redactor import verifier
from pfsense_redactor.redactor import PfSenseRedactor

PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "CANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIV0123\n"
    "-----END RSA PRIVATE KEY-----"
)

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJDQU5BUllfSldUIn0"
    ".dBjftJeZ4CVPmB92K27uhbUJU1p1r6wW1gFWFOEjXk"
)

CREDENTIAL_URL = "https://svcacct:CANARY_URLPASSWORD@feeds.vendor.invalid/list"


def config(inner):
    """A minimal but structurally realistic pfSense config"""
    return f"<pfsense><version>23.1</version>{inner}</pfsense>"


def rendered(result):
    """Every character the verifier would print or serialise for `result`

    Used to assert the negative: whatever a finding says, it must not be
    possible to recover the secret from it.
    """
    return " ".join(verifier.describe(result)) + " " + repr(result)


class TestFindingsCarryNoSecret:
    """A finding is published. It must be safe to publish."""

    def test_a_finding_names_a_path_a_kind_and_a_length(self):
        """What an operator needs to go and look"""
        result = verifier.scan_shapes(config(f"<blob>{PEM}</blob>"))

        assert not result.clean
        finding = next(f for f in result.findings
                       if f.finding_id == 'retained-private-key')
        assert finding.path == 'document'
        assert finding.kind == 'pem-private-key'
        assert finding.length > 0
        assert finding.reason

    def test_a_finding_carries_no_value(self):
        """Not the value"""
        result = verifier.scan_shapes(config(f"<blob>{PEM}</blob>"))
        assert "CANARYPRIVATEKEY" not in rendered(result)

    def test_a_finding_carries_no_prefix(self):
        """Nor a prefix of it - a JWT header names the issuer"""
        result = verifier.scan_shapes(config(f"<blob>{JWT}</blob>"))
        text = rendered(result)

        assert "eyJhbGci" not in text
        assert "eyJ" not in text

    def test_a_finding_carries_no_hash(self):
        """Nor a hash - a short secret's hash is brute-forceable

        Asserted by construction: the dataclass has no field that could hold
        one, so this fails if a field is ever added.
        """
        import dataclasses  # pylint: disable=import-outside-toplevel

        names = {f.name for f in dataclasses.fields(verifier.VerificationFinding)}
        assert names == {'finding_id', 'path', 'kind', 'length', 'reason'}

    @pytest.mark.parametrize("placeholder", ["REDACTED", "[REDACTED]"])
    def test_an_already_redacted_url_password_is_not_a_finding(self, placeholder):
        """Reporting the redaction as the leak is worse than useless

        Both spellings, because square brackets are not safe inside URL
        userinfo and the tool writes the bare form there.
        """
        assert verifier.scan_shapes(config(
            f"<url>https://svcacct:{placeholder}@feeds.example/list</url>"
        )).clean

    def test_a_credential_url_finding_carries_no_url(self):
        """A credential-bearing URL is a credential and a location at once"""
        result = verifier.scan_shapes(config(f"<url>{CREDENTIAL_URL}</url>"))
        text = rendered(result)

        assert not result.clean
        assert "CANARY_URLPASSWORD" not in text
        assert "feeds.vendor.invalid" not in text


class TestShapeScan:
    """Strategy A: what the serialised output looks like on its own terms"""

    def test_finds_a_private_key(self):
        """The case that matters most"""
        assert not verifier.scan_shapes(config(f"<x>{PEM}</x>")).clean

    def test_finds_a_jwt(self):
        """A token is a credential"""
        assert not verifier.scan_shapes(config(f"<x>{JWT}</x>")).clean

    def test_finds_a_credential_bearing_url(self):
        """Matched on the userinfo separator, not on a list of schemes"""
        assert not verifier.scan_shapes(config(f"<x>{CREDENTIAL_URL}</x>")).clean

    def test_finds_a_credential_url_with_an_unknown_scheme(self):
        """A scheme the transformer has never heard of is still a URL"""
        result = verifier.scan_shapes(
            config("<x>vendorproto://svc:CANARY_PW@host.invalid/p</x>")
        )
        assert not result.clean

    def test_finds_a_base64_wrapped_private_key(self):
        """An encoding is not a protection here either"""
        import base64  # pylint: disable=import-outside-toplevel
        wrapped = base64.b64encode(PEM.encode()).decode()
        assert not verifier.scan_shapes(config(f"<x>{wrapped}</x>")).clean

    def test_finds_a_double_base64_wrapped_private_key(self):
        """Two layers, independently of the transformer's decoder"""
        import base64  # pylint: disable=import-outside-toplevel
        once = base64.b64encode(PEM.encode()).decode()
        twice = base64.b64encode(once.encode()).decode()
        assert not verifier.scan_shapes(config(f"<x>{twice}</x>")).clean

    def test_a_clean_document_is_clean(self):
        """The control. A verifier that always fires says nothing."""
        result = verifier.scan_shapes(config(
            "<system><hostname>fw</hostname>"
            "<password>[REDACTED]</password></system>"
        ))
        assert result.clean

    def test_placeholders_are_not_findings(self):
        """Reporting the redaction as the leak would be worse than useless"""
        assert verifier.scan_shapes(config(
            "<a>[REDACTED]</a><b>[REDACTED_CERT_OR_KEY]</b>"
            "<c>XX:XX:XX:XX:XX:XX</c><d>XXX.XXX.XXX.XXX</d>"
        )).clean

    def test_a_public_key_is_not_a_private_key(self):
        """The boundary of the rule, pinned"""
        assert verifier.scan_shapes(config(
            "<x>-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----</x>"
        )).clean

    def test_low_entropy_runs_are_not_findings(self):
        """An all-zero field satisfies the shape and carries nothing"""
        assert verifier.scan_shapes(config("<x>" + "0" * 64 + "</x>")).clean

    def test_a_uuid_is_not_a_finding(self):
        """pfSense uses them as object identifiers"""
        assert verifier.scan_shapes(
            config("<x>550e8400-e29b-41d4-a716-446655440000</x>")
        ).clean


class TestRetentionScan:
    """Strategy B: which input values came out the other side unchanged"""

    def test_finds_a_value_that_survived(self):
        """The check that classifies nothing"""
        root = ET.fromstring(config("<pkg><blob>CANARYSURVIVINGVALUE123456</blob></pkg>"))
        tracked = verifier.collect_input_values(root)
        result = verifier.scan_retention(tracked, config(
            "<pkg><blob>CANARYSURVIVINGVALUE123456</blob></pkg>"
        ))

        assert not result.clean
        assert result.findings[0].path == 'pfsense/pkg/blob'

    def test_reports_no_finding_when_the_value_was_replaced(self):
        """The control"""
        root = ET.fromstring(config("<pkg><blob>CANARYSURVIVINGVALUE123456</blob></pkg>"))
        tracked = verifier.collect_input_values(root)

        assert verifier.scan_retention(
            tracked, config("<pkg><blob>[REDACTED]</blob></pkg>")
        ).clean

    def test_re_wrapping_does_not_defeat_the_comparison(self):
        """A serialiser that re-wraps a long value has not redacted it"""
        value = "CANARYWRAPPEDVALUE" + "A" * 40
        root = ET.fromstring(config(f"<pkg><blob>{value}</blob></pkg>"))
        tracked = verifier.collect_input_values(root)
        wrapped = value[:20] + "\n  " + value[20:]

        assert not verifier.scan_retention(
            tracked, config(f"<pkg><blob>{wrapped}</blob></pkg>")
        ).clean

    def test_finds_a_surviving_attribute_value(self):
        """Attributes are values too"""
        xml = config('<pkg><ep token="CANARYATTRIBUTEVALUE9876"/></pkg>')
        root = ET.fromstring(xml)
        result = verifier.scan_retention(verifier.collect_input_values(root), xml)

        assert not result.clean
        assert result.findings[0].path == 'pfsense/pkg/ep[@token]'
        assert result.findings[0].kind == 'attribute'

    def test_short_values_are_not_compared(self):
        """Below the floor, retention stops distinguishing a leak from a word"""
        xml = config("<pkg><mode>aggressive</mode></pkg>")
        root = ET.fromstring(xml)

        assert verifier.scan_retention(verifier.collect_input_values(root), xml).clean

    @pytest.mark.parametrize(
        "inner,why",
        [
            ("<refid>CANARYREFIDVALUE1234</refid>", "structural element"),
            ("<blob>[REDACTED_CERT_OR_KEY]</blob>", "our own placeholder"),
            ("<cmd>/usr/local/bin/checkreload_long_name</cmd>", "absolute path"),
            ("<descr>an ordinary rule description here</descr>", "contains whitespace"),
            ("<url>https://doc.example/index.php/Setup_Package</url>", "outside the alphabet"),
            ("<host>collector.internal.example.invalid</host>", "outside the alphabet"),
        ],
    )
    def test_documented_exclusions(self, inner, why):
        """Each exclusion asserted on its own, so the set cannot quietly widen"""
        xml = config(f"<pkg>{inner}</pkg>")
        root = ET.fromstring(xml)

        assert verifier.scan_retention(
            verifier.collect_input_values(root), xml
        ).clean, why

    def test_allowlisted_values_are_excluded(self):
        """The operator asked to keep these"""
        xml = config("<pkg><host>time.nist.gov.example</host></pkg>")
        root = ET.fromstring(xml)
        tracked = verifier.collect_input_values(
            root, frozenset({'time.nist.gov.example'})
        )

        assert verifier.scan_retention(tracked, xml).clean

    def test_duplicate_values_are_reported_once(self):
        """A value repeated across a hundred rules is one problem, not a hundred"""
        value = "CANARYREPEATEDVALUE12345"
        inner = "".join(f"<rule><blob>{value}</blob></rule>" for _ in range(50))
        xml = config(f"<filter>{inner}</filter>")
        root = ET.fromstring(xml)

        result = verifier.scan_retention(verifier.collect_input_values(root), xml)
        assert result.count == 1

    def test_tracking_is_bounded(self):
        """A pathological document must not make the verifier the problem"""
        inner = "".join(
            f"<n><blob>CANARYUNIQUEVALUE{n:08d}</blob></n>"
            for n in range(verifier.MAX_TRACKED_VALUES + 500)
        )
        root = ET.fromstring(config(f"<pkg>{inner}</pkg>"))

        assert len(verifier.collect_input_values(root)) <= verifier.MAX_TRACKED_VALUES


class TestDefectInjection:
    """Break the transformer on purpose. The verifier must notice unaided."""

    @staticmethod
    def _run_with_broken_transformer(monkeypatch, xml):
        """Redact `xml` with redact_element neutered, and verify the result

        Neutering the traversal entirely is the strongest form of the test:
        the transformer's statistics, its retained-value list and its warnings
        all report a clean run, because from its point of view nothing needed
        doing. Only something reading the output can tell otherwise.
        """
        monkeypatch.setattr(
            PfSenseRedactor, 'redact_element',
            lambda self, element, redact_ips=True, redact_domains=True: None
        )

        redactor = PfSenseRedactor()
        root = ET.fromstring(xml)
        tracked = verifier.collect_input_values(root)
        redactor.redact_element(root)
        candidate = ET.tostring(root, encoding='unicode')

        findings = list(verifier.scan_shapes(candidate).findings)
        findings.extend(verifier.scan_retention(tracked, candidate).findings)
        return redactor, verifier.build_result(findings)

    def test_a_retained_private_key_is_caught(self, monkeypatch):
        """1. The transformer keeps a PEM key and says nothing"""
        redactor, result = self._run_with_broken_transformer(
            monkeypatch, config(f"<pkg><vendorblob>{PEM}</vendorblob></pkg>")
        )

        assert redactor.stats['secrets_redacted'] == 0, "transformer must be silent"
        assert not result.clean
        assert any(f.finding_id == 'retained-private-key' for f in result.findings)

    def test_a_retained_jwt_is_caught(self, monkeypatch):
        """2. And a token"""
        _, result = self._run_with_broken_transformer(
            monkeypatch, config(f"<pkg><apitoken>{JWT}</apitoken></pkg>")
        )
        assert any(f.finding_id == 'retained-jwt' for f in result.findings)

    def test_a_retained_base64_wrapped_key_is_caught(self, monkeypatch):
        """3. And an encoded one"""
        import base64  # pylint: disable=import-outside-toplevel
        wrapped = base64.b64encode(PEM.encode()).decode()

        _, result = self._run_with_broken_transformer(
            monkeypatch, config(f"<pkg><payload>{wrapped}</payload></pkg>")
        )
        assert any(f.finding_id == 'retained-private-key' for f in result.findings)

    def test_a_retained_canary_in_an_unknown_field_is_caught(self, monkeypatch):
        """4. The case no shape rule covers: an ordinary-looking secret

        Nothing about CANARY_ADV_UNKNOWN_FIELD_SECRET looks like key material.
        It is caught because it came out of the input unchanged, which is the
        one thing the shape rules cannot tell you.
        """
        _, result = self._run_with_broken_transformer(
            monkeypatch,
            config("<pkg><mqtt_login>CANARYUNKNOWNFIELDSECRET42</mqtt_login></pkg>")
        )

        assert any(f.finding_id == 'retained-input-value' for f in result.findings)
        assert "CANARYUNKNOWNFIELD" not in rendered(result)

    def test_a_retained_credential_url_is_caught(self, monkeypatch):
        """5. And a credential in a URL"""
        _, result = self._run_with_broken_transformer(
            monkeypatch, config(f"<pkg><updateurl>{CREDENTIAL_URL}</updateurl></pkg>")
        )
        assert any(f.finding_id == 'retained-url-credential' for f in result.findings)

    def test_no_finding_contains_secret_text(self, monkeypatch):
        """6. Across every injected defect at once"""
        _, result = self._run_with_broken_transformer(monkeypatch, config(
            f"<pkg><a>{PEM}</a><b>{JWT}</b><c>{CREDENTIAL_URL}</c>"
            "<d>CANARYUNKNOWNFIELDSECRET42</d></pkg>"
        ))
        text = rendered(result)

        assert not result.clean
        for secret in ("CANARYPRIVATEKEY", "eyJ", "CANARY_URLPASSWORD",
                       "CANARYUNKNOWNFIELD", "svcacct"):
            assert secret not in text, secret

    def test_a_correct_run_produces_no_findings(self, monkeypatch):
        """7a. The control: with the transformer intact, the same input is clean"""
        del monkeypatch  # the transformer is deliberately left alone here
        xml = config(f"<pkg><a>{PEM}</a><b>{JWT}</b><c>{CREDENTIAL_URL}</c></pkg>")

        redactor = PfSenseRedactor(aggressive=True)
        root = ET.fromstring(xml)
        tracked = verifier.collect_input_values(root)
        redactor.redact_element(root)
        candidate = ET.tostring(root, encoding='unicode')

        findings = list(verifier.scan_shapes(candidate).findings)
        findings.extend(verifier.scan_retention(tracked, candidate).findings)
        assert verifier.build_result(findings).clean


class TestFalsePositiveVolume:
    """7b. A report nobody can read is a report nobody reads"""

    @pytest.mark.parametrize(
        "sample", ["default-config.xml", "test-config1.xml", "test-config2.xml"]
    )
    def test_real_configs_stay_reviewable(self, sample, tmp_path, cli_runner):
        """Findings on a real config must fit on a screen

        Not zero: these samples do contain values that survive verbatim, and
        saying so is the verifier working. The number has to stay small enough
        that an operator reads it rather than dismissing it.
        """
        del tmp_path, cli_runner  # the sample files are read directly
        from pathlib import Path  # pylint: disable=import-outside-toplevel

        path = Path(__file__).resolve().parents[2] / "test-configs" / sample
        if not path.exists():  # pragma: no cover - repo integrity
            pytest.skip(f"missing sample: {path}")

        redactor = PfSenseRedactor(aggressive=True, redact_descriptions=True)
        tree = ET.parse(path)
        root = tree.getroot()
        tracked = verifier.collect_input_values(root)
        redactor.known_refids = redactor._collect_refids(root)  # pylint: disable=protected-access
        redactor.redact_element(root)
        candidate = ET.tostring(root, encoding='unicode')

        findings = list(verifier.scan_shapes(candidate).findings)
        findings.extend(verifier.scan_retention(tracked, candidate).findings)
        result = verifier.build_result(findings)

        assert result.count <= 15, [f.path for f in result.findings]


class TestVerifierNeedsNoXmlParser:
    """The verifier never parses XML, and must not import a parser to say so

    Codacy flags `import xml.etree.ElementTree` as XXE-prone wherever it
    appears. On this module the finding is wrong - there is no ET.parse and no
    ET.fromstring here, only annotations - but the import was also genuinely
    unnecessary, so it moved under TYPE_CHECKING rather than being argued with
    or suppressed. These tests stop it coming back.
    """

    def test_verifier_does_not_import_elementtree_at_runtime(self):
        """The assertion the fix has to satisfy

        The module-level import is enough. Re-importing inside the test would
        return the same cached module object, so it would add no freshness -
        and a module-level `import xml.etree.ElementTree as ET` in verifier.py
        would put `ET` in this namespace either way, which is what is checked.
        """
        assert "ET" not in vars(verifier)

    def test_the_module_imports_no_xml_library_at_all(self):
        """Not even for annotations

        The verifier is handed an already-parsed tree and walks it. Depending
        on the parser that produced it - in code or in types - would tie the
        one component meant not to share the transformer's assumptions to the
        transformer's library.
        """
        assert "import xml" not in self._source()

    def test_the_module_parses_no_xml(self):
        """The reason no XML library is needed, asserted against the source

        If a parse call is ever added here, the justification stops holding
        and this fails - which is the point at which the defusedxml question
        genuinely needs answering rather than dismissing.
        """
        source = self._source()

        for parser in ("ET.parse(", "ET.fromstring(", "ET.XML(", "XMLParser(",
                       "parse(", "fromstring("):
            assert parser not in source, f"verifier.py now parses XML via {parser}"

    @staticmethod
    def _source():
        """verifier.py's source text"""
        from pathlib import Path  # pylint: disable=import-outside-toplevel

        return (Path(__file__).resolve().parents[2]
                / "pfsense_redactor" / "verifier.py").read_text(encoding="utf-8")

    def test_it_still_walks_a_tree_it_is_given(self):
        """The control: dropping the import must not have dropped the feature"""
        root = ET.fromstring(config("<pkg><blob>CANARYSTILLWALKSVALUE99</blob></pkg>"))

        tracked = verifier.collect_input_values(root)
        assert any(item.path == 'pfsense/pkg/blob' for item in tracked)


class TestVerifierIntegration:
    """How redactor.py uses it, and what it does when it cannot"""

    def test_serialisation_matches_what_is_written(self, tmp_path):
        """Verifying anything but the written bytes verifies the wrong thing"""
        tree = ET.ElementTree(ET.fromstring(config("<system><a>b</a></system>")))
        target = tmp_path / "out.xml"
        tree.write(str(target), encoding='utf-8', xml_declaration=True)

        assert PfSenseRedactor.serialise_tree(tree) == target.read_text(encoding='utf-8')

    def test_verification_is_available_in_a_normal_installation(self):
        """The package ships verifier.py, so it must import"""
        from pfsense_redactor.redactor import (  # pylint: disable=import-outside-toplevel
            verification_is_available,
        )
        assert verification_is_available()

    def test_an_unavailable_verifier_is_not_a_pass(self, monkeypatch):
        """None must never be read as 'verified clean'

        The single-file deployment has no verifier.py beside it. Reporting that
        as a clean verification would be exactly the fail-open behaviour the
        verifier exists to remove.
        """
        monkeypatch.setattr('pfsense_redactor.redactor.VERIFIER', None)

        result = PfSenseRedactor().verify_candidate_output(config(f"<x>{PEM}</x>"))
        assert result is None

    def test_a_run_reports_its_verification(self, tmp_path, cli_runner):
        """The operator is told, in every mode"""
        source = tmp_path / "config.xml"
        source.write_text(config(f"<pkg><vendorblob>{PEM}</vendorblob></pkg>"))

        _, stdout, stderr = cli_runner.run(str(source), str(tmp_path / "out.xml"))
        assert "Independent verification" in stdout + stderr

    def test_verification_result_is_kept_on_the_redactor(self, tmp_path):
        """PR 3 needs a verdict to gate on; this is where it comes from"""
        source = tmp_path / "config.xml"
        source.write_text(config("<system><hostname>fw</hostname></system>"))

        redactor = PfSenseRedactor()
        redactor.redact_config(str(source), str(tmp_path / "out.xml"))

        assert redactor.last_verification is not None
        assert redactor.last_verification.clean
