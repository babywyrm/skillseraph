#!/usr/bin/env sh
# install.sh — skillseraph installer for macOS and Linux
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/babywyrm/skillseraph/main/install.sh | sh
#
# What this does:
#   1. Ensures uv is available (installs it if not, using the official installer).
#   2. Installs skillseraph as a uv tool so `skillseraph` lands on your PATH.
#   3. Prints a quick-start hint.
#
# uv is the runtime engine; skillseraph is uv-native and depends on it.
# If you already have uv, it is not reinstalled.
#
# Uninstall:
#   uv tool uninstall skillseraph
#
set -eu

REPO="https://github.com/babywyrm/skillseraph"
GIT_REF="${SKILLSERAPH_REF:-main}"   # override with SKILLSERAPH_REF=v0.1.0 to pin

# ── helpers ─────────────────────────────────────────────────────────────────

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31merr\033[0m %s\n' "$*" >&2; exit 1; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"
}

# ── OS / arch check ──────────────────────────────────────────────────────────

case "$(uname -s)" in
    Linux|Darwin) ;;
    *) err "unsupported OS: $(uname -s). skillseraph runs on Linux and macOS." ;;
esac

# ── ensure uv ────────────────────────────────────────────────────────────────

if command -v uv >/dev/null 2>&1; then
    ok "uv already installed: $(uv --version)"
else
    say "uv not found — installing via the official installer..."
    need_cmd curl
    # The official uv installer (https://docs.astral.sh/uv/getting-started/installation/)
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # The installer writes to ~/.local/bin (Linux) or ~/.cargo/bin (some setups).
    # Source the env file it drops, if present.
    UV_ENV="${HOME}/.local/bin/env"
    if [ -f "$UV_ENV" ]; then
        # shellcheck disable=SC1090
        . "$UV_ENV"
    fi

    # Re-check
    command -v uv >/dev/null 2>&1 || err "uv installed but not on PATH. Add ~/.local/bin to PATH and re-run."
    ok "uv installed: $(uv --version)"
fi

# ── install skillseraph ───────────────────────────────────────────────────────

say "Installing skillseraph@${GIT_REF} via uv tool install..."

uv tool install "git+${REPO}@${GIT_REF}"

# ── verify ───────────────────────────────────────────────────────────────────

if command -v skillseraph >/dev/null 2>&1; then
    ok "skillseraph installed: $(skillseraph --version)"
else
    # uv tool bin dir may not be in PATH yet
    UV_BIN="$(uv tool bin-dir 2>/dev/null || echo "${HOME}/.local/bin")"
    printf '\n'
    printf '\033[1;33mNote:\033[0m skillseraph is at %s/skillseraph\n' "$UV_BIN"
    printf 'Add the following to your shell profile and restart your shell:\n'
    printf '\n'
    printf '  export PATH="%s:$PATH"\n' "$UV_BIN"
    printf '\n'
fi

# ── quick-start hint ──────────────────────────────────────────────────────────

printf '\n'
printf '\033[1;32mDone!\033[0m Try it:\n'
printf '\n'
printf '  skillseraph .                          # scan current directory\n'
printf '  skillseraph . --fail-on high           # CI gate (default threshold)\n'
printf '  skillseraph . --platform cursor -v     # verbose Cursor scan\n'
printf '  skillseraph --help                     # full usage\n'
printf '\n'
printf 'Docs: %s\n' "$REPO"
