"""Tests for monitoring-exception blind-spot detection."""

from pathlib import Path

from skillseraph.checks.monitoring_bypass import check_monitoring_bypass

DUMMY = Path("config.yaml")


class TestMonitoringBypass:
    def test_disable_audit_detected(self):
        findings = check_monitoring_bypass(DUMMY, "audit: disabled")
        assert any(f.check == "monitoring_disabled" for f in findings)

    def test_logging_false_detected(self):
        findings = check_monitoring_bypass(DUMMY, '{"logging": false}')
        assert any(f.check == "monitoring_disabled" for f in findings)

    def test_wildcard_exception_detected(self):
        findings = check_monitoring_bypass(DUMMY, 'exceptions: ["*"]')
        assert any(f.check == "broad_monitoring_exception" for f in findings)

    def test_rule_disable_detected(self):
        findings = check_monitoring_bypass(DUMMY, "disable_rule: Terminal shell in container")
        assert any(f.check == "monitoring_rule_disabled" for f in findings)

    def test_benign_config_no_findings(self):
        findings = check_monitoring_bypass(
            DUMMY, '{"logging": true, "audit": "enabled", "level": "info"}'
        )
        assert findings == []
