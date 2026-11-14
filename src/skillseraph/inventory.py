"""Inventory of the agent surface a scan read: MCP servers, extensions, hooks, files.

No verdicts. Paths are relative to the scan target, MCP commands are
redacted, and only env key names and URL hosts are kept, so the file can be
shared for fleet audits.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .checks import redact
from .checks.extensions import extension_entries
from .checks.lifecycle import hook_events
from .checks.mcp_servers import URL_FIELDS, command_line, server_entries
from .models import ScanResult


@dataclass(frozen=True)
class McpServer:
    path: str
    name: str
    transport: str
    command: str
    host: str
    env_keys: list[str]


@dataclass(frozen=True)
class Extension:
    path: str
    id: str
    version: str
    source: str


@dataclass(frozen=True)
class Hook:
    path: str
    event: str


@dataclass(frozen=True)
class Inventory:
    files: list[str]
    mcp_servers: list[McpServer]
    extensions: list[Extension]
    hooks: list[Hook]


def _path_labels(target: Path) -> list[tuple[str, str]]:
    """Absolute prefixes to hide in commands, longest first; the home wins when it is the target."""
    roots = [(target, "<target>")]
    try:
        roots.append((Path.home(), "~"))
    except RuntimeError:
        pass
    labels: dict[str, str] = {}
    for root, label in roots:
        for spelling in {str(root), str(root.resolve())} - {"/"}:
            labels[spelling] = label
    return sorted(labels.items(), key=lambda item: len(item[0]), reverse=True)


def _server(rel: str, name: str, server: dict[str, object], labels: list[tuple[str, str]]) -> McpServer:
    url = next(
        (v for k in URL_FIELDS if isinstance(v := server.get(k), str) and v.lower().startswith(("http://", "https://"))),
        "",
    )
    command = command_line(server)
    for prefix, label in labels:
        command = command.replace(prefix, label)
    command = redact(command)[:200]
    env = server.get("env", server.get("environment"))
    return McpServer(
        path=rel,
        name=redact(name),
        transport="http" if url else "stdio" if command else "unknown",
        command=command,
        host=urlparse(url).hostname or "",
        env_keys=sorted(k for k in env if isinstance(k, str)) if isinstance(env, dict) else [],
    )


def build_inventory(result: ScanResult) -> Inventory:
    files: list[str] = []
    servers: list[McpServer] = []
    extensions: list[Extension] = []
    hooks: list[Hook] = []
    labels = _path_labels(result.target)
    for path in sorted(set(result.scanned_paths)):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(result.target).as_posix()
        files.append(rel)
        servers.extend(_server(rel, name, server, labels) for name, server in server_entries(path, content))
        extensions.extend(
            Extension(rel, redact(ext_id), redact(version), source)
            for ext_id, version, source in extension_entries(path, content)
        )
        hooks.extend(Hook(rel, redact(event)) for event in hook_events(path, content))
    return Inventory(
        files=files,
        mcp_servers=sorted(servers, key=lambda s: (s.path, s.name)),
        extensions=sorted(extensions, key=lambda e: (e.path, e.id)),
        hooks=sorted(hooks, key=lambda h: (h.path, h.event)),
    )


def write_inventory(inventory: Inventory, path: Path) -> None:
    path.write_text(json.dumps({"version": __version__, **asdict(inventory)}, indent=2))


_IDENTITY = {"files": (), "mcp_servers": ("path", "name"), "extensions": ("path", "id"), "hooks": ("path", "event")}

_Indexed = dict[str, dict[str, dict[str, object]]]


class InventoryError(ValueError):
    """An inventory file is unreadable or not in the shape --inventory writes."""


@dataclass(frozen=True)
class Change:
    kind: str  # "+" added, "~" changed, "-" removed
    section: str
    label: str
    fields: tuple[str, ...] = ()


def _index(data: object) -> _Indexed:
    """Entries keyed by identity per section; InventoryError on any shape it does not expect."""
    if not isinstance(data, dict):
        raise InventoryError("inventory must be a JSON object")
    indexed: _Indexed = {}
    for section, identity in _IDENTITY.items():
        entries = data.get(section, [])
        if not isinstance(entries, list):
            raise InventoryError(f"inventory {section} must be a list")
        indexed[section] = {}
        for entry in entries:
            if section == "files":
                if not isinstance(entry, str):
                    raise InventoryError("inventory files must be strings")
                indexed[section][entry] = {}
                continue
            if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) for k in identity):
                raise InventoryError(f"inventory {section} entries need string {', '.join(identity)}")
            indexed[section][" ".join(entry[k] for k in identity)] = entry
    return indexed


def load_inventory(path: Path) -> _Indexed:
    try:
        return _index(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"cannot read inventory {path}: {exc}") from exc


def diff_inventory(old: _Indexed, inventory: Inventory) -> list[Change]:
    new = _index(asdict(inventory))
    changes: list[Change] = []
    for section in _IDENTITY:
        before, after = old[section], new[section]
        changes += [Change("+", section, key) for key in sorted(after.keys() - before.keys())]
        changes += [
            Change("~", section, key, tuple(sorted(
                f for f in after[key].keys() | before[key].keys() if before[key].get(f) != after[key].get(f)
            )))
            for key in sorted(after.keys() & before.keys())
            if before[key] != after[key]
        ]
        changes += [Change("-", section, key) for key in sorted(before.keys() - after.keys())]
    return changes
