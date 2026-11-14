"""Kubernetes ValidatingAdmissionWebhook for skillseraph.

Scans every ConfigMap ``data`` and ``binaryData`` key. Rejects the admission
request if findings at/above the configured threshold are detected.

Run standalone:  python -m skillseraph.webhook
Env:
  FAIL_ON         severity threshold (default: high)
  LISTEN_PORT     webhook port (default: 8443)
  TLS_CERT_FILE   path to TLS cert (required by K8s webhooks)
  TLS_KEY_FILE    path to TLS key
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import ssl
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .models import Severity
from .scanner import scan_file

FAIL_ON = os.environ.get("FAIL_ON", "high")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8443"))
TLS_CERT = os.environ.get("TLS_CERT_FILE", "/certs/tls.crt")
TLS_KEY = os.environ.get("TLS_KEY_FILE", "/certs/tls.key")

_CONFIGMAP_KEY = re.compile(r"[-._a-zA-Z0-9]{1,253}")

THRESHOLD = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "any": Severity.INFO,
    "none": None,
}


def _invalid(check: str, title: str, key: str) -> dict[str, str]:
    return {"check": check, "severity": "critical", "title": title, "key": key[:64]}


def _scan_configmap_data(data: dict[str, str], binary_data: dict[str, str] | None = None) -> list[dict[str, str]]:
    """Write every key to a temp dir and scan it.

    Key names are not trusted to pick what gets scanned: a volume's
    ``items[].path`` can mount any key at an agent config path.
    """
    findings = []
    files: list[tuple[str, bytes]] = []
    for key, content in data.items():
        files.append((key, content.encode()))
    for key, encoded in (binary_data or {}).items():
        try:
            files.append((key, base64.b64decode(encoded, validate=True)))
        except binascii.Error:
            findings.append(_invalid("invalid_binary_data", "binaryData value is not valid base64", key))
    with tempfile.TemporaryDirectory(prefix="seraph-") as td:
        sev = THRESHOLD[FAIL_ON]
        for key, raw in files:
            if not _CONFIGMAP_KEY.fullmatch(key) or key in (".", ".."):
                findings.append(_invalid("invalid_configmap_key", "Data key is not a valid ConfigMap key", key))
                continue
            path = Path(td) / key
            path.write_bytes(raw)
            for f in scan_file(path, governed=True):
                if sev and f.severity.score >= sev.score:
                    findings.append({"check": f.check, "severity": f.severity.value, "title": f.title, "key": key})
    return findings


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        review = body.get("request", {})
        obj = review.get("object", {})
        data = obj.get("data") or {}
        binary_data = obj.get("binaryData") or {}
        ns = review.get("namespace", "")
        name = obj.get("metadata", {}).get("name", "")

        findings = _scan_configmap_data(data, binary_data) if data or binary_data else []
        allowed = len(findings) == 0

        verdict: dict[str, object] = {"uid": review.get("uid", ""), "allowed": allowed}
        if not allowed:
            msg = f"skillseraph: {len(findings)} finding(s) in {ns}/{name}: " + "; ".join(
                f"[{f['severity']}] {f['check']}: {f['title']} (key={f['key']})" for f in findings[:5]
            )
            verdict["status"] = {"code": 403, "message": msg}
        response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": verdict,
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format: str, *args: object) -> None:
        pass


def serve() -> None:
    server = HTTPServer(("0.0.0.0", LISTEN_PORT), WebhookHandler)
    if os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"skillseraph webhook listening on :{LISTEN_PORT} (fail_on={FAIL_ON})")
    server.serve_forever()


if __name__ == "__main__":
    serve()
