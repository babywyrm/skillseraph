"""Tests for container/orchestrator runtime escape-surface detection."""

from pathlib import Path

from skillseraph.checks.runtime_escape import check_runtime_escape

DUMMY = Path("skill.json")


class TestRuntimeSocket:
    def test_docker_socket_path_detected(self):
        findings = check_runtime_escape(DUMMY, '{"commands": ["cat /var/run/docker.sock"]}')
        assert any(f.check == "container_runtime_socket" for f in findings)

    def test_docker_socket_via_curl_unix_socket_detected(self):
        findings = check_runtime_escape(
            DUMMY, 'curl --unix-socket /var/run/docker.sock http://localhost/containers/json'
        )
        assert any(f.check == "container_runtime_socket" for f in findings)

    def test_containerd_socket_detected(self):
        findings = check_runtime_escape(DUMMY, "ctr --address /run/containerd/containerd.sock")
        assert any(f.check == "container_runtime_socket" for f in findings)


class TestKubeletAndSAToken:
    def test_kubelet_api_port_detected(self):
        findings = check_runtime_escape(DUMMY, "curl -k https://10.0.0.1:10250/run/")
        assert any(f.check == "kubelet_api_access" for f in findings)

    def test_service_account_token_path_detected(self):
        findings = check_runtime_escape(
            DUMMY, "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
        )
        assert any(f.check == "sa_token_access" for f in findings)


class TestHostNamespacePrivileged:
    def test_privileged_true_detected(self):
        findings = check_runtime_escape(DUMMY, "  privileged: true")
        assert any(f.check == "host_namespace_or_privileged" for f in findings)

    def test_host_pid_detected(self):
        findings = check_runtime_escape(DUMMY, '{"hostPID": true}')
        assert any(f.check == "host_namespace_or_privileged" for f in findings)

    def test_nsenter_escape_detected(self):
        findings = check_runtime_escape(DUMMY, "nsenter --target 1 --mount --uts --net")
        assert any(f.check == "host_namespace_or_privileged" for f in findings)


class TestBenign:
    def test_clean_config_no_findings(self):
        findings = check_runtime_escape(
            DUMMY, '{"commands": ["pytest -q", "ruff check ."], "privileged": false}'
        )
        assert findings == []
