"""Phase 8: --strict, the fail-closed mode

Strict mode exists for output that may be read by anyone, indefinitely. Its
whole value is that it has no silent failure path, so these tests are mostly
about what it refuses and what it does *not* leave behind when it refuses.

The two properties every case below asserts together:

    non-zero exit  AND  no artefact

Either on its own is the failure mode this mode was built to remove. A gate
that reports a problem and still writes the file is what --fail-on-warn used to
be; a run that writes nothing and exits 0 is worse.

Every value here is synthetic.
"""
from __future__ import annotations

import base64
import json
import os
import stat
import xml.etree.ElementTree as ET

import pytest

from pfsense_redactor.redactor import ExitCode, MAX_XML_DEPTH, PfSenseRedactor

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

# Nothing in here is a secret, nothing survives verbatim, and the schema
# version is one the tool knows. Strict mode must produce output for it, or the
# mode is a refusal generator rather than a gate.
CLEAN_CONFIG = (
    "<pfsense><version>23.1</version>"
    "<system><hostname>fw</hostname>"
    "<user><name>admin</name><password>hunter2</password></user></system>"
    "<interfaces><wan><if>igb0</if><ipaddr>dhcp</ipaddr></wan></interfaces>"
    "</pfsense>"
)


def write(tmp_path, xml, name="config.xml"):
    """Put `xml` in a file and return its path"""
    path = tmp_path / name
    path.write_text(xml, encoding="utf-8")
    return path


def wrap(inner, version="23.1"):
    """A package config carrying `inner`"""
    return (f"<pfsense><version>{version}</version><installedpackages>"
            f"<vendorpkg><config>{inner}</config></vendorpkg>"
            f"</installedpackages></pfsense>")


class TestStrictModeProducesOutputWhenItCan:
    """The control. A mode that always refuses protects nothing."""

    def test_a_clean_config_succeeds(self, tmp_path, run_redactor):
        """Strict mode is a gate, not a wall"""
        source = write(tmp_path, CLEAN_CONFIG)
        out = tmp_path / "out.xml"

        result = run_redactor(source, out, "--strict")

        assert result.returncode == ExitCode.CLEAN, result.stderr
        assert out.exists()
        ET.fromstring(out.read_text())

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
    def test_the_output_is_not_world_readable(self, tmp_path, run_redactor):
        """Strict output is still a redacted configuration"""
        source = write(tmp_path, CLEAN_CONFIG)
        out = tmp_path / "out.xml"
        run_redactor(source, out, "--strict")

        mode = stat.S_IMODE(out.stat().st_mode)
        assert not mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH)

    def test_strict_implies_the_strongest_scanning(self, tmp_path, run_redactor):
        """--aggressive and --redact-descriptions are on, without asking"""
        source = write(tmp_path, wrap(
            "<syslogtarget>198.18.51.77</syslogtarget>"
            "<descr>CEO Jane Doe personal laptop</descr>"
        ))
        out = tmp_path / "out.xml"
        run_redactor(source, out, "--strict")

        if out.exists():
            text = out.read_text()
            assert "198.18.51.77" not in text
            assert "Jane Doe" not in text


# A value that no rule in the transformer recognises: not a secret-named
# element, not a key shape, not high-entropy enough to report. It survives the
# transformation intact, and only re-reading the output can tell. This is what
# strict mode has to refuse.
SURVIVOR = "<mqtt_login_string>CANARYUNKNOWNFIELDSECRET42</mqtt_login_string>"


class TestStrictModeRemovesKeyMaterial:
    """Classes that are removed rather than refused

    Strict mode is not a refusal generator. Where the transformer can remove
    the material, it does, and the output is produced - the mode's value is in
    what happens when it *cannot*.
    """

    @pytest.mark.parametrize(
        "inner,absent",
        [
            (f"<vendorblob>{PEM}</vendorblob>", "CANARYPRIVATEKEY"),
            (f'<endpoint blob="{PEM}"/>', "CANARYPRIVATEKEY"),
            (f"<payload>{base64.b64encode(PEM.encode()).decode()}</payload>",
             "LS0tLS1CRUdJTiBSU0Eg"),
            (f"<blob>{base64.b64encode(base64.b64encode(PEM.encode())).decode()}</blob>",
             "TFMwdExTMUNSVWRK"),
            (f"<apitoken>{JWT}</apitoken>", "eyJhbGciOiJIUzI1NiIs"),
            ("<sitekey>deadbeefdeadbeefdeadbeefcafefeedcafefeed</sitekey>",
             "deadbeefdeadbeef"),
        ],
        ids=["pem-element", "pem-attribute", "base64-pem", "double-base64-pem",
             "jwt", "hex-only"],
    )
    def test_the_material_is_gone_and_output_is_produced(
        self, tmp_path, run_redactor, inner, absent
    ):
        """Removed, verified clean, and written"""
        source = write(tmp_path, wrap(inner))
        out = tmp_path / "out.xml"

        result = run_redactor(source, out, "--strict")

        assert result.returncode == ExitCode.CLEAN, result.stderr
        assert out.exists()
        assert absent not in out.read_text()


class TestStrictModeWithholdsOutput:
    """Non-zero exit and no artefact, when something survives"""

    def test_a_surviving_value_means_no_output(self, tmp_path, run_redactor):
        """The case no shape rule covers, and the reason the mode exists"""
        source = write(tmp_path, wrap(SURVIVOR))
        out = tmp_path / "out.xml"

        result = run_redactor(source, out, "--strict")

        assert result.returncode == ExitCode.VERIFIER_FINDING
        assert not out.exists(), "strict mode produced an artefact"

    def test_an_existing_destination_is_left_alone(self, tmp_path, run_redactor):
        """A refusal must not destroy what was already there"""
        source = write(tmp_path, wrap(SURVIVOR))
        out = tmp_path / "out.xml"
        out.write_bytes(b"<pfsense><previous/></pfsense>")
        before = out.read_bytes()

        result = run_redactor(source, out, "--strict", "--force")

        assert result.returncode != 0
        assert out.read_bytes() == before

    def test_no_xml_reaches_stdout(self, tmp_path, run_redactor):
        """A redirected stdout is an artefact like any other"""
        source = write(tmp_path, wrap(SURVIVOR))

        result = run_redactor(source, "--stdout", "--strict")

        assert result.returncode != 0
        assert result.stdout.strip() == ""

    def test_no_temporary_files_are_left_behind(self, tmp_path, run_redactor):
        """Not even the ones a partial write would have created"""
        source = write(tmp_path, wrap(SURVIVOR))
        run_redactor(source, tmp_path / "out.xml", "--strict")

        leftovers = {p.name for p in tmp_path.iterdir()} - {"config.xml"}
        assert not leftovers, leftovers

    def test_the_input_is_untouched(self, tmp_path, run_redactor):
        """A refusal reads the input and nothing else"""
        source = write(tmp_path, wrap(SURVIVOR))
        before = source.read_bytes()

        run_redactor(source, tmp_path / "out.xml", "--strict")

        assert source.read_bytes() == before

    def test_a_transformer_defect_is_caught_by_the_verifier(self, tmp_path, run_redactor):
        """The assurance the mode rests on, stated as a property

        SURVIVOR is a defect in the transformer's coverage rather than an
        injected one: nothing in its rules recognises the element or the value.
        The run is refused anyway, because something other than the transformer
        looked at the output.
        """
        source = write(tmp_path, wrap(SURVIVOR))
        result = run_redactor(source, tmp_path / "out.xml", "--strict")

        assert "verification" in result.stderr.lower()
        assert "CANARYUNKNOWNFIELDSECRET42" not in result.stderr


class TestStrictModeRejectsInput:
    """Structures and schemas there is no basis for processing"""

    def test_an_unsupported_root_is_rejected(self, tmp_path, run_redactor):
        """Every redaction decision rests on element names meaning what we think"""
        source = write(tmp_path, "<opnsense><system><password>x</password></system></opnsense>")
        out = tmp_path / "out.xml"

        result = run_redactor(source, out, "--strict")

        assert result.returncode == ExitCode.INPUT_REJECTED
        assert not out.exists()

    def test_an_unsupported_schema_version_is_rejected(self, tmp_path, run_redactor):
        """An unfamiliar schema is where name-driven coverage is weakest"""
        source = write(tmp_path, wrap("<a>b</a>", version="99.9"))
        out = tmp_path / "out.xml"

        result = run_redactor(source, out, "--strict")

        assert result.returncode == ExitCode.INPUT_REJECTED
        assert "99.9" in result.stderr
        assert not out.exists()

    def test_a_supported_schema_version_is_accepted(self, tmp_path, run_redactor):
        """The control, across the range the tool claims"""
        for version in ("2.9", "18.2", "23.09.1"):
            source = write(tmp_path, CLEAN_CONFIG.replace("23.1", version))
            result = run_redactor(source, tmp_path / f"out-{version}.xml", "--strict")
            assert result.returncode == ExitCode.CLEAN, f"{version}: {result.stderr}"

    def test_excessive_nesting_is_rejected(self, tmp_path, run_redactor):
        """Refused, rather than traversed until the interpreter gives up"""
        depth = MAX_XML_DEPTH + 50
        source = write(
            tmp_path,
            f"<pfsense><version>23.1</version>{'<a>' * depth}x{'</a>' * depth}</pfsense>"
        )
        out = tmp_path / "out.xml"

        result = run_redactor(source, out, "--strict")

        assert result.returncode == ExitCode.INPUT_REJECTED
        assert "Traceback" not in result.stderr
        assert not out.exists()

    def test_oversized_text_is_rejected(self, tmp_path, run_redactor):
        """Discarding part of the configuration is not a successful run

        Free text rather than a run of one character, so the value is not
        redacted as a blob before the size bound is reached - the bound is what
        this is about.
        """
        oversized = "the quick brown fox jumps over the lazy dog " * 28_000
        source = write(
            tmp_path,
            f"<pfsense><version>23.1</version><installedpackages><vendor>"
            f"<config><vendornotes>{oversized}</vendornotes></config>"
            "</vendor></installedpackages></pfsense>"
        )
        out = tmp_path / "out.xml"

        result = run_redactor(source, out, "--strict")

        assert result.returncode == ExitCode.INPUT_REJECTED
        assert not out.exists()

    def test_oversized_text_is_rejected_outside_strict_mode_too(
        self, tmp_path, run_redactor
    ):
        """Silently losing config data is not acceptable in any mode

        <hostname> rather than a package field, because the refusal is about
        text the tool actually scans. A value in an element no pass touches is
        copied through whole - nothing is discarded, so there is nothing to
        refuse.
        """
        oversized = "the quick brown fox jumps over the lazy dog " * 28_000
        source = write(
            tmp_path,
            f"<pfsense><version>23.1</version><system><hostname>{oversized}"
            "</hostname></system></pfsense>"
        )
        out = tmp_path / "out.xml"

        result = run_redactor(source, out)

        assert result.returncode == ExitCode.INPUT_REJECTED
        assert not out.exists()


class TestIncompleteTraversalFailsClosed:
    """A subtree the traversal never reached is unredacted, not clean

    redact_element stops descending at MAX_XML_DEPTH and counts it.
    _check_structural_limits normally refuses such a document first, so this
    should be unreachable through the CLI - but nothing was reading the
    counter, so if the two limits ever disagreed the run would emit a document
    containing elements it had never examined, and report success.

    Refused in every mode, not only under a gate: the elements below the cut
    were not redacted, and the run knows only that it stopped.
    """

    @pytest.fixture
    def too_deep(self, tmp_path):
        """A document past MAX_XML_DEPTH"""
        depth = MAX_XML_DEPTH + 50
        return write(
            tmp_path,
            f"<pfsense><version>23.1</version>{'<a>' * depth}"
            f"CANARYBELOWTHECUT42{'</a>' * depth}</pfsense>"
        )

    def test_the_traversal_records_that_it_stopped(self, too_deep):
        """The premise: the counter this now gates on is actually set"""
        redactor = PfSenseRedactor()
        redactor.redact_element(ET.parse(too_deep).getroot())

        assert redactor.stats['depth_limit_hits'] > 0

    @pytest.mark.parametrize("flags", [[], ["--aggressive"], ["--strict"]],
                             ids=["default", "aggressive", "strict"])
    def test_it_is_refused_with_input_rejected(self, too_deep, tmp_path, run_redactor, flags):
        """Non-zero, and the same code in every mode"""
        result = run_redactor(too_deep, tmp_path / "out.xml", *flags)

        assert result.returncode == ExitCode.INPUT_REJECTED, result.stderr

    def test_it_creates_no_output(self, too_deep, tmp_path, run_redactor):
        """Nothing to find and share"""
        out = tmp_path / "out.xml"
        run_redactor(too_deep, out)

        assert not out.exists()

    def test_it_preserves_an_existing_output(self, too_deep, tmp_path, run_redactor):
        """And does not destroy what was already there"""
        out = tmp_path / "out.xml"
        out.write_bytes(b"<pfsense><previous/></pfsense>")
        before = out.read_bytes()

        run_redactor(too_deep, out, "--force")

        assert out.read_bytes() == before

    def test_it_emits_no_xml_to_stdout(self, too_deep, run_redactor):
        """A redirected stdout is an artefact like any other"""
        result = run_redactor(too_deep, "--stdout")

        assert result.returncode != 0
        assert result.stdout.strip() == ""
        assert "CANARYBELOWTHECUT42" not in result.stdout

    def test_the_reason_names_the_depth(self, too_deep, tmp_path, run_redactor):
        """An operator has to be able to tell this from any other refusal"""
        result = run_redactor(too_deep, tmp_path / "out.xml")

        assert "nested deeper" in result.stderr or "nests more than" in result.stderr


class TestStrictModeHasNoImplicitConfiguration:
    """Output must not depend on where the tool was run"""

    @pytest.fixture
    def workdir(self, tmp_path):
        """A working directory holding an implicit allow-list"""
        (tmp_path / ".pfsense-allowlist").write_text(
            "megacorp-holdings.example\n198.18.51.77\n"
        )
        write(tmp_path, wrap(
            "<syslogtarget>198.18.51.77</syslogtarget>"
            "<note>ships to collector.megacorp-holdings.example</note>"
        ))
        return tmp_path

    def test_the_implicit_allowlist_is_not_loaded(self, workdir, run_redactor):
        """A file in the working directory must not weaken a public-sharing run"""
        result = run_redactor("config.xml", "out.xml", "--strict", cwd=workdir)

        out = workdir / "out.xml"
        if out.exists():
            text = out.read_text()
            assert "198.18.51.77" not in text
            assert "megacorp-holdings.example" not in text
        assert "ignoring the allow-list" in result.stderr

    def test_ignoring_it_is_announced(self, workdir, run_redactor):
        """An operator relying on that file has to find out"""
        result = run_redactor("config.xml", "out.xml", "--strict", cwd=workdir)

        assert ".pfsense-allowlist" in result.stderr

    def test_an_explicit_allowlist_is_used_and_announced(self, tmp_path, run_redactor):
        """--allowlist-file is the only way in, and it says so"""
        allowlist = tmp_path / "allow.txt"
        allowlist.write_text("time.nist.gov.example\n")
        source = write(tmp_path, CLEAN_CONFIG)

        result = run_redactor(
            source, tmp_path / "out.xml", "--strict", "--allowlist-file", allowlist
        )

        assert "Loaded allow-list" in result.stderr
        assert str(allowlist) in result.stderr
        assert result.returncode == ExitCode.CLEAN


class TestStrictModeRejectsInPlace:
    """There is nowhere to withhold output to when the destination is the source"""

    def test_strict_inplace_is_a_usage_error(self, tmp_path, run_redactor):
        """And the original is untouched"""
        source = write(tmp_path, CLEAN_CONFIG)
        before = source.read_bytes()

        result = run_redactor(source, "--strict", "--inplace", "--force")

        assert result.returncode != 0
        assert "--strict" in result.stderr
        assert source.read_bytes() == before


class TestExitCodes:
    """A caller needs to tell apart why a run failed"""

    def test_a_clean_run_exits_zero(self, tmp_path, run_redactor):
        """The baseline"""
        source = write(tmp_path, CLEAN_CONFIG)
        assert run_redactor(source, tmp_path / "o.xml", "--strict").returncode == 0

    def test_unparseable_input(self, tmp_path, run_redactor):
        """2, not the same code as a retained secret"""
        source = write(tmp_path, "<pfsense><unclosed></pfsense>")
        result = run_redactor(source, tmp_path / "o.xml", "--strict")
        assert result.returncode == ExitCode.INPUT_REJECTED

    def test_a_retained_value(self, tmp_path, run_redactor):
        """3 - the transformer knew it kept something"""
        source = write(tmp_path, wrap(
            "<blob>Q0FOQVJZX0JBU0U2NEJMT0JfQ0FOQVJZX0JBU0U2NEJMT0JfQ0FOQVJZ</blob>"
        ))
        result = run_redactor(source, tmp_path / "o.xml", "--fail-on-warn")
        assert result.returncode == ExitCode.RETAINED_VALUE

    def test_a_verifier_finding(self, tmp_path, run_redactor):
        """4 - only something re-reading the output could tell"""
        source = write(tmp_path, wrap(SURVIVOR))
        result = run_redactor(source, tmp_path / "o.xml", "--strict")
        assert result.returncode == ExitCode.VERIFIER_FINDING

    @pytest.mark.parametrize(
        "flags,why",
        [
            (["--inplace"], "--inplace without --force"),
            (["--strict", "--inplace", "--force"], "--strict with --inplace"),
            (["--quiet", "--verbose"], "mutually exclusive verbosity"),
        ],
    )
    def test_usage_errors_exit_one(self, tmp_path, run_redactor, flags, why):
        """1, not argparse's 2

        The documented scheme has always said 1 means a usage error, and
        nothing produced it: every one of these went through parser.error,
        which exits 2. argparse still exits 2 for a command line it rejects
        itself - an unknown flag - and that overlap is documented.
        """
        source = write(tmp_path, CLEAN_CONFIG)

        result = run_redactor(source, *flags)

        assert result.returncode == ExitCode.USAGE, f"{why}: {result.stderr[:200]}"

    def test_an_unknown_flag_still_exits_two(self, tmp_path, run_redactor):
        """argparse's own convention, left alone and documented"""
        source = write(tmp_path, CLEAN_CONFIG)

        result = run_redactor(source, "--no-such-flag")

        assert result.returncode == 2

    def test_the_codes_are_distinct(self, tmp_path, run_redactor):
        """The property the finding was about"""
        malformed = write(tmp_path, "<pfsense><unclosed></pfsense>", "bad.xml")
        retained = write(tmp_path, wrap(
            "<blob>Q0FOQVJZX0JBU0U2NEJMT0JfQ0FOQVJZX0JBU0U2NEJMT0JfQ0FOQVJZ</blob>"
        ), "retained.xml")

        parse_failure = run_redactor(malformed, tmp_path / "a.xml").returncode
        gate_failure = run_redactor(retained, tmp_path / "b.xml", "--fail-on-warn").returncode

        assert parse_failure != gate_failure
        assert parse_failure != 0 and gate_failure != 0

    def test_every_non_zero_code_stays_non_zero(self, tmp_path, run_redactor):
        """Integrations that only test for success are unaffected"""
        cases = [
            (write(tmp_path, "<pfsense><unclosed></pfsense>", "a.xml"), []),
            (write(tmp_path, wrap(SURVIVOR), "b.xml"), ["--strict"]),
            (write(tmp_path, wrap("<a>x</a>", version="99.9"), "c.xml"), ["--strict"]),
            (write(tmp_path, "<opnsense><a>x</a></opnsense>", "d.xml"), ["--strict"]),
        ]
        for index, (source, flags) in enumerate(cases):
            result = run_redactor(source, tmp_path / f"out{index}.xml", *flags)
            assert result.returncode != 0, (source, flags)


class TestJsonReport:
    """A sharing decision that something other than a human can check"""

    @pytest.fixture
    def report(self, tmp_path, run_redactor):
        """A report from a run that found something"""
        source = write(tmp_path, wrap(
            f"<vendorblob>{PEM}</vendorblob>"
            f"<apitoken>{JWT}</apitoken>"
            + SURVIVOR
        ))
        path = tmp_path / "report.json"
        run_redactor(source, tmp_path / "out.xml", "--strict", "--report-json", path)
        return path

    def test_it_is_written_even_when_the_run_failed(self, report):
        """A run that withheld output is exactly when a caller needs the reason"""
        assert report.exists()

    def test_it_is_valid_json_with_the_documented_shape(self, report):
        """A schema nothing validates is prose in braces"""
        data = json.loads(report.read_text())

        assert data['schema_version'] == 1
        assert data['tool']['name'] == 'pfsense-redactor'
        assert set(data['input']) >= {'sha256', 'bytes', 'root_tag', 'config_version'}
        assert data['verdict'] in {'clean', 'findings', 'rejected'}
        assert isinstance(data['findings'], list)
        assert isinstance(data['retained'], list)
        assert data['exit_code'] != 0

    def test_findings_carry_metadata_only(self, report):
        """Path, kind and length. Never a value."""
        data = json.loads(report.read_text())

        for finding in data['findings']:
            assert set(finding) == {'id', 'path', 'kind', 'length'}
            assert isinstance(finding['length'], int)

    def test_no_secret_text_appears_anywhere_in_it(self, report):
        """Asserted over the whole file, not per field

        A field-by-field check passes the moment a secret reaches a field
        nobody thought to check.
        """
        text = report.read_text()

        for secret in ("CANARYPRIVATEKEY", "BEGIN RSA PRIVATE KEY", "eyJ",
                       "CANARYUNKNOWNFIELDSECRET", "dBjftJeZ"):
            assert secret not in text, secret

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
    def test_it_is_not_world_readable(self, report):
        """It names the path of everything the run decided to keep"""
        mode = stat.S_IMODE(report.stat().st_mode)
        assert not mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH)

    def test_a_clean_run_reports_clean(self, tmp_path, run_redactor):
        """The other half of the verdict"""
        source = write(tmp_path, CLEAN_CONFIG)
        path = tmp_path / "report.json"

        run_redactor(source, tmp_path / "out.xml", "--strict", "--report-json", path)
        data = json.loads(path.read_text())

        assert data['verdict'] == 'clean'
        assert data['exit_code'] == 0
        assert data['findings'] == []
        assert data['counts']['verifier_findings'] == 0

    def test_it_records_the_mode_the_run_used(self, tmp_path, run_redactor):
        """A report that does not say how it was produced cannot be trusted"""
        source = write(tmp_path, CLEAN_CONFIG)
        path = tmp_path / "report.json"

        run_redactor(source, tmp_path / "out.xml", "--strict", "--report-json", path)
        mode = json.loads(path.read_text())['mode']

        assert mode['strict'] is True
        assert mode['aggressive'] is True
        assert mode['redact_descriptions'] is True

    def test_it_records_every_allowlist_source(self, tmp_path, run_redactor):
        """An allow-list weakens redaction, so the report has to name it"""
        allowlist = tmp_path / "allow.txt"
        allowlist.write_text("time.nist.gov.example\n")
        source = write(tmp_path, CLEAN_CONFIG)
        path = tmp_path / "report.json"

        run_redactor(source, tmp_path / "out.xml", "--strict",
                     "--allowlist-file", allowlist, "--report-json", path)

        assert str(allowlist) in json.loads(path.read_text())['mode']['allowlist_files']

    @pytest.mark.parametrize(
        "verdict,setup",
        [
            ('clean', 'clean'),
            ('rejected', 'unparseable'),
            ('findings', 'survivor'),
            ('error', 'unwritable'),
        ],
    )
    def test_every_verdict_is_reachable_and_distinct(
        self, tmp_path, run_redactor, verdict, setup
    ):
        """All four mappings, each from a run that really produces that code

        'findings' is a statement about the configuration. An I/O or internal
        failure is a statement about the run, and reporting it as 'findings'
        tells a pipeline the config still holds secrets when the disk was
        actually full - which is why 'error' exists.
        """
        report = tmp_path / "report.json"

        if setup == 'clean':
            source = write(tmp_path, CLEAN_CONFIG)
        elif setup == 'unparseable':
            source = write(tmp_path, "<pfsense><unclosed></pfsense>")
        elif setup == 'survivor':
            source = write(tmp_path, wrap(SURVIVOR))
        else:
            source = write(tmp_path, CLEAN_CONFIG)

        target = tmp_path / "out.xml"
        if setup == 'unwritable':
            # A destination whose parent directory does not exist. The
            # candidate is produced and verified, and the failure lands in the
            # atomic writer - which is an I/O failure, not a finding about the
            # configuration. A directory would not do: it has more than one
            # name, so it is refused by the hard-link guard before any of this.
            target = tmp_path / "no-such-directory" / "out.xml"

        run_redactor(source, target, "--strict", "--force", "--report-json", report)

        assert json.loads(report.read_text())['verdict'] == verdict

    def test_it_works_outside_strict_mode(self, adversarial_canary, run_redactor, tmp_path):
        """--report-json is not strict-only; --dry-run is the usual pairing"""
        path = tmp_path / "report.json"
        result = run_redactor(adversarial_canary, "--dry-run", "--report-json", path)

        assert result.returncode == 0
        data = json.loads(path.read_text())
        assert data['mode']['dry_run'] is True
        assert data['retained'], "the canary retains values, so they must be listed"
