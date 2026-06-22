"""Kubernetes ValidatingAdmissionWebhook for skillseraph.

Scans ConfigMap/Secret data keys that match agent-config patterns. Rejects the
admission request if findings at/above the configured threshold are detected.

Run standalone:  python -m skillseraph.webhook
Env:
  FAIL_ON         severity threshold (default: high)
  LISTEN_PORT     webhook port (default: 8443)
  TLS_CERT_FILE   path to TLS cert (required by K8s webhooks)
  TLS_KEY_FILE    path to TLS key
"""

from __future__ import annotations

import json
import os
import ssl
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .models import Severity
from .scanner import scan_directory

FAIL_ON = os.environ.get("FAIL_ON", "high")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8443"))
TLS_CERT = os.environ.get("TLS_CERT_FILE", "/certs/tls.crt")
TLS_KEY = os.environ.get("TLS_KEY_FILE", "/certs/tls.key")

AGENT_CONFIG_KEYS = {
    "AGENTS.md", "CLAUDE.md", "SKILL.md", "rules.mdc",
    "copilot-instructions.md", "hooks.json", "mcp.json",
    "devin.md", "system_prompt.md",
}

THRESHOLD = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "any": Severity.INFO,
    "none": None,
}


def _scan_configmap_data(data: dict[str, str]) -> list[dict]:
    """Write data keys to a temp dir and scan them."""
    findings = []
    with tempfile.TemporaryDirectory(prefix="seraph-") as td:
        td_path = Path(td)
        for key, content in data.items():
            if not any(key.endswith(suffix) or key in AGENT_CONFIG_KEYS
                       for suffix in (".md", ".mdc", ".json", ".yaml", ".yml")):
                continue
            (td_path / key).write_text(content)
        result = scan_directory(td_path)
        sev = THRESHOLD.get(FAIL_ON)
        for f in result.findings:
            if sev and f.severity.score >= sev.score:
                findings.append({"check": f.check, "severity": f.severity.value, "title": f.title, "key": str(f.path.name)})
    return findings


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        review = body.get("request", {})
        obj = review.get("object", {})
        data = obj.get("data", {})
        ns = review.get("namespace", "")
        name = obj.get("metadata", {}).get("name", "")

        findings = _scan_configmap_data(data) if data else []
        allowed = len(findings) == 0

        response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": review.get("uid", ""),
                "allowed": allowed,
            },
        }
        if not allowed:
            msg = f"skillseraph: {len(findings)} finding(s) in {ns}/{name}: " + "; ".join(
                f"[{f['severity']}] {f['check']}: {f['title']} (key={f['key']})" for f in findings[:5]
            )
            response["response"]["status"] = {"code": 403, "message": msg}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass


def serve():
    server = HTTPServer(("0.0.0.0", LISTEN_PORT), WebhookHandler)
    if os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"skillseraph webhook listening on :{LISTEN_PORT} (fail_on={FAIL_ON})")
    server.serve_forever()


if __name__ == "__main__":
    serve()
