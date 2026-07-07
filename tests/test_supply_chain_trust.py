"""Tests for skill-source trust & auto-deploy detection."""

from pathlib import Path

from skillseraph.checks.supply_chain_trust import check_supply_chain_trust

DUMMY = Path("skills.json")


class TestAutoDeploy:
    def test_auto_approve_true_detected(self):
        findings = check_supply_chain_trust(
            DUMMY, '{"skill_source": {"url": "https://feed.example", "auto_approve": true}}'
        )
        assert any(f.check == "skill_source_autodeploy" for f in findings)

    def test_require_approval_false_detected(self):
        findings = check_supply_chain_trust(DUMMY, "require_approval: false")
        assert any(f.check == "skill_source_autodeploy" for f in findings)

    def test_skip_human_review_detected(self):
        findings = check_supply_chain_trust(DUMMY, "  skip_human_review: yes")
        assert any(f.check == "skill_source_autodeploy" for f in findings)

    def test_auto_approve_false_not_flagged(self):
        findings = check_supply_chain_trust(
            DUMMY, '{"auto_approve": false, "require_approval": true}'
        )
        assert not any(f.check == "skill_source_autodeploy" for f in findings)


class TestTrustedSourceBypass:
    def test_trusted_feed_detected(self):
        findings = check_supply_chain_trust(
            DUMMY, '{"feed": {"trusted": true, "url": "https://community.example"}}'
        )
        assert any(f.check == "trusted_source_bypass" for f in findings)

    def test_untrusted_source_not_flagged(self):
        findings = check_supply_chain_trust(
            DUMMY, '{"feed": {"trusted": false, "url": "https://community.example"}}'
        )
        assert not any(f.check == "trusted_source_bypass" for f in findings)


class TestRemoteFeed:
    def test_remote_plugin_registry_detected(self):
        findings = check_supply_chain_trust(
            DUMMY, "plugin_registry: https://community.example/registry.json"
        )
        assert any(f.check == "remote_skill_feed" for f in findings)

    def test_remote_skill_feed_json_detected(self):
        findings = check_supply_chain_trust(
            DUMMY, '{"skill_feed": "https://community.example/feed"}'
        )
        assert any(f.check == "remote_skill_feed" for f in findings)


class TestBenign:
    def test_clean_config_no_findings(self):
        findings = check_supply_chain_trust(
            DUMMY,
            '{"skill_source": {"url": "https://feed.example", '
            '"auto_approve": false, "require_approval": true, "trusted": false}}',
        )
        assert findings == []
