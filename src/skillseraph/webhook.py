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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .models import Severity
from .scanner import scan_file

FAIL_ON = os.environ.get("FAIL_ON", "high")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8443"))
TLS_CERT = os.environ.get("TLS_CERT_FILE", "/certs/tls.crt")
TLS_KEY = os.environ.get("TLS_KEY_FILE", "/certs/tls.key")

MAX_BODY = 4 * 1024 * 1024
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


class ReviewError(ValueError):
    """The request is not a well-formed AdmissionReview."""


def _mapping(node: object, key: str) -> dict[str, object]:
    value = node.get(key) if isinstance(node, dict) else None
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ReviewError(f"{key} must be an object")
    return value


def _strings(node: dict[str, object], key: str) -> dict[str, str]:
    value = _mapping(node, key)
    if not all(isinstance(v, str) for v in value.values()):
        raise ReviewError(f"{key} values must be strings")
    return {str(k): str(v) for k, v in value.items()}


class WebhookHandler(BaseHTTPRequestHandler):
    timeout = 5

    def _error(self, code: int, message: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": message}).encode())

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._error(400, "Content-Length must be an integer")
        if length < 0:
            return self._error(400, "Content-Length must not be negative")
        if length > MAX_BODY:
            return self._error(413, f"body over {MAX_BODY} bytes")
        try:
            body = json.loads(self.rfile.read(length)) if length else {}
            if not isinstance(body, dict):
                raise ReviewError("body must be an object")
            review = _mapping(body, "request")
            obj = _mapping(review, "object")
            data = _strings(obj, "data")
            binary_data = _strings(obj, "binaryData")
        except ValueError as exc:  # json.JSONDecodeError is a ValueError
            return self._error(400, str(exc))
        ns = review.get("namespace", "")
        name = _mapping(obj, "metadata").get("name", "")

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


def make_server(address: tuple[str, int]) -> ThreadingHTTPServer:
    """One thread per connection, so a stalled client cannot hold up reviews.

    ponytail: threads are unbounded; a flood of connections is left to the
    API server's own limits. Upgrade: a bounded pool.
    """
    return ThreadingHTTPServer(address, WebhookHandler)


def serve() -> None:
    # The webhook configuration fails open, so a typo here or a gate the API
    # server cannot reach would silently admit everything.
    if FAIL_ON not in THRESHOLD:
        raise SystemExit(f"FAIL_ON must be one of {', '.join(THRESHOLD)}, not {FAIL_ON!r}")
    if not (os.path.isfile(TLS_CERT) and os.path.isfile(TLS_KEY)):
        raise SystemExit(f"TLS cert and key are required: {TLS_CERT}, {TLS_KEY}")
    server = make_server(("0.0.0.0", LISTEN_PORT))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(TLS_CERT, TLS_KEY)
    # Handshake in the connection's thread, not in the accept loop.
    server.socket = ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    print(f"skillseraph webhook listening on :{LISTEN_PORT} (fail_on={FAIL_ON})")
    server.serve_forever()


if __name__ == "__main__":
    serve()
