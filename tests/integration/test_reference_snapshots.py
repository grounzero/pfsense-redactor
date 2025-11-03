"""
Reference snapshot tests - end-to-end validation against real sample files

These tests run the CLI with various flag combinations and compare outputs
to reference files. Set UPDATE_REFERENCE=1 to regenerate snapshots.
"""
import pytest


# Test modes with their corresponding CLI flags
TEST_MODES = {
    "default": [],
    "keep_private": ["--keep-private-ips"],
    "anonymise": ["--anonymise"],
    "no_domains": ["--no-redact-domains", "--keep-private-ips"],
    "aggressive": ["--aggressive", "--keep-private-ips"],
    "no_ips": ["--no-redact-ips"],
}


@pytest.mark.slow
@pytest.mark.parametrize("mode_name,flags", TEST_MODES.items())
def test_reference_snapshot(
    sample_files,
    mode_name,
    flags,
    cli_runner,
    reference_dir,
    temp_output_dir,
    update_reference
):
    """
    Test each sample file against reference outputs for each mode

    This test runs the redactor with different flag combinations and compares
    the output to stored reference files. Use UPDATE_REFERENCE=1 to regenerate.
    """
    for sample_file in sample_files:
        sample_name = sample_file.stem

        # Create reference directory structure
        reference_sample_dir = reference_dir / sample_name
        reference_sample_dir.mkdir(parents=True, exist_ok=True)

        reference_file = reference_sample_dir / f"{mode_name}.xml"
        output_file = temp_output_dir / f"{sample_name}_{mode_name}.xml"

        # Run the redactor
        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file),
            flags=flags,
            expect_success=True
        )

        assert exit_code == 0, f"Redactor failed for {sample_name} with mode {mode_name}"
        assert output_file.exists(), f"Output file not created: {output_file}"

        if update_reference:
            # Update reference file
            import shutil
            shutil.copy(output_file, reference_file)
            print(f"Updated reference: {reference_file}")
        else:
            # Compare with reference
            if not reference_file.exists():
                pytest.skip(
                    f"Reference file not found: {reference_file}\n"
                    f"Run with UPDATE_REFERENCE=1 to create it"
                )

            # Read both files and compare
            output_content = output_file.read_text()
            reference_content = reference_file.read_text()

            # Normalize whitespace for comparison
            output_lines = [line.rstrip() for line in output_content.splitlines()]
            reference_lines = [line.rstrip() for line in reference_content.splitlines()]

            if output_lines != reference_lines:
                # Show diff for debugging
                import difflib
                diff = difflib.unified_diff(
                    reference_lines,
                    output_lines,
                    fromfile=str(reference_file),
                    tofile=str(output_file),
                    lineterm=''
                )
                diff_text = '\n'.join(diff)
                pytest.fail(
                    f"Output differs from reference for {sample_name}/{mode_name}\n"
                    f"Diff:\n{diff_text[:2000]}"  # Limit diff output
                )


@pytest.mark.slow
def test_stdout_mode(sample_files, cli_runner, reference_dir, update_reference):
    """Test --stdout mode captures XML correctly"""
    for sample_file in sample_files:
        sample_name = sample_file.stem

        # Run with --stdout
        exit_code, stdout, stderr = cli_runner.run_to_stdout(
            str(sample_file),
            flags=["--keep-private-ips"]
        )

        assert exit_code == 0
        assert stdout, "No stdout output captured"
        assert "<?xml" in stdout, "XML declaration missing from stdout"

        # Verify it's valid XML
        import xml.etree.ElementTree as ET
        try:
            ET.fromstring(stdout)
        except ET.ParseError as e:
            pytest.fail(f"Invalid XML in stdout: {e}")

        # Compare with reference if not updating
        reference_file = reference_dir / sample_name / "stdout.xml"

        if update_reference:
            reference_file.parent.mkdir(parents=True, exist_ok=True)
            reference_file.write_text(stdout)
            print(f"Updated reference stdout: {reference_file}")
        elif reference_file.exists():
            reference_content = reference_file.read_text()
            output_lines = [line.rstrip() for line in stdout.splitlines()]
            reference_lines = [line.rstrip() for line in reference_content.splitlines()]

            assert output_lines == reference_lines, (
                f"Stdout output differs from reference for {sample_name}"
            )


@pytest.mark.slow
def test_stats_stderr_mode(sample_files, cli_runner, stats_parser):
    """Test --stats-stderr prints stats to stderr when using --stdout"""
    for sample_file in sample_files:
        # Run with --stdout --stats-stderr
        exit_code, stdout, stderr = cli_runner.run_to_stdout(
            str(sample_file),
            flags=[]
        )

        assert exit_code == 0
        assert stdout, "No stdout output"
        assert "Redaction summary:" in stderr, "Stats not in stderr"

        # Verify stats are parseable
        stats = stats_parser.parse(stderr)
        assert stats, "No stats parsed from stderr"
