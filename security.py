"""Security functions for amux-server.

Extracted to a standalone module so they can be imported by unit tests
without triggering the full server initialization (mkcert, tmux, etc.).
"""

import os
import secrets
from pathlib import Path
from urllib.parse import parse_qs, urlparse


# ── Authentication ───────────────────────────────────────────────────────────

def load_or_create_auth_token(token_file: Path, amux_home: Path) -> str:
    """Load existing auth token or generate a new one.
    Set AMUX_AUTH_TOKEN env var to override. Set to "none" to disable."""
    env_token = os.environ.get("AMUX_AUTH_TOKEN", "")
    if env_token:
        return "" if env_token.lower() == "none" else env_token
    if token_file.exists():
        token = token_file.read_text().strip()
        if token:
            return token
    token = secrets.token_urlsafe(32)
    amux_home.mkdir(parents=True, exist_ok=True)
    token_file.write_text(token + "\n")
    os.chmod(str(token_file), 0o600)
    return token


# Paths that don't require auth (public assets, share links, health check)
PUBLIC_PATHS = frozenset({
    "/", "/manifest.json", "/sw.js", "/icon.svg", "/icon.png",
    "/icon-192.png", "/icon-512.png", "/release-notes",
    "/api/release-notes",
})
PUBLIC_PREFIXES = ("/s/", "/api/share/", "/invite/")

# Paths that look like static assets but still require auth
AUTH_REQUIRED_PATHS = frozenset({"/ca"})


def check_auth(auth_token: str, method: str, path: str,
               auth_header: str = "", full_url: str = "") -> bool:
    """Return True if request is authorized.
    Checks bearer token in header, then _token query param fallback for SSE."""
    if not auth_token:
        return True  # auth disabled
    if path in PUBLIC_PATHS or any(path.startswith(p) for p in PUBLIC_PREFIXES):
        return True
    # Static assets (CSS/JS/images served from /) bypass auth, except AUTH_REQUIRED_PATHS
    if (method == "GET" and not path.startswith("/api/")
            and not path.startswith("/proxy/") and path not in AUTH_REQUIRED_PATHS):
        return True
    # Check Authorization header
    if auth_header == f"Bearer {auth_token}":
        return True
    # Check query param fallback (for EventSource/SSE which can't set headers)
    url = full_url or path
    token_qs = parse_qs(urlparse(url).query).get("_token", [""])[0]
    if token_qs == auth_token:
        return True
    return False


# ── Filesystem access control ────────────────────────────────────────────────

SENSITIVE_PATHS = frozenset({
    ".ssh", ".gnupg", ".aws", ".kube", ".netrc", ".npmrc",
    ".docker", ".config/gcloud", ".config/gh",
})

BLOCKED_SYSTEM_PATHS = frozenset({
    "/etc/shadow", "/etc/sudoers", "/etc/master.passwd",
    "/private/etc/shadow", "/private/etc/sudoers",
    "/var/db/sudo", "/private/var/db/sudo",
})

BLOCKED_SYSTEM_PREFIXES = (
    "/etc/ssh/", "/private/etc/ssh/",
    "/var/run/secrets/", "/run/secrets/",
)


def is_path_allowed(p: Path, auth_token_file: Path = None) -> bool:
    """Check if a resolved path is safe to access via file APIs.
    Blocks sensitive dotfile directories, system paths, and the auth token file."""
    try:
        resolved = p.resolve()
    except (OSError, ValueError):
        return False
    resolved_str = str(resolved)
    if resolved_str in BLOCKED_SYSTEM_PATHS:
        return False
    if any(resolved_str.startswith(pfx) for pfx in BLOCKED_SYSTEM_PREFIXES):
        return False
    if auth_token_file:
        try:
            if resolved == auth_token_file.resolve():
                return False
        except (OSError, ValueError):
            pass
    home = Path.home().resolve()
    try:
        rel = resolved.relative_to(home)
        parts = rel.parts
        for sensitive in SENSITIVE_PATHS:
            sens_parts = Path(sensitive).parts
            if parts[:len(sens_parts)] == sens_parts:
                return False
    except ValueError:
        pass  # outside home — allow (e.g. /tmp, project dirs)
    return True


def safe_note_path(note_rel: str, base: Path) -> Path | None:
    """Resolve a note relative path and verify it stays within the base directory.
    Returns the resolved Path if safe, or None if traversal detected."""
    if not note_rel or note_rel.startswith("/"):
        return None
    candidate = (base / note_rel).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError:
        return None
    return candidate


# ── CORS origin validation ───────────────────────────────────────────────────

def is_origin_allowed(origin: str, lan_ip: str = "") -> bool:
    """Check if a CORS origin should receive Access-Control-Allow-Origin.
    Allows localhost, loopback, server LAN IP, and Tailscale *.ts.net."""
    if not origin:
        return False
    parsed = urlparse(origin)
    host = parsed.hostname or ""
    return (
        host in ("localhost", "127.0.0.1", "0.0.0.0")
        or (lan_ip and host == lan_ip)
        or host.endswith(".ts.net")
    )


# ── tmux send_keys validation ───────────────────────────────────────────────

ALLOWED_TMUX_KEYS = frozenset({
    "Enter", "Escape", "Tab", "BTab", "Space", "BSpace",
    "Up", "Down", "Left", "Right", "Home", "End",
    "PageUp", "PageDown", "IC", "DC",  # Insert, Delete
    "C-c", "C-d", "C-z", "C-l", "C-a", "C-e", "C-k", "C-u",
    "C-r", "C-p", "C-n", "C-b", "C-f", "C-w",
    "M-b", "M-f", "M-d",  # Alt/Meta combos
    "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12",
    "y", "n", "q",  # common single-char confirmations
})


def validate_tmux_key(keys: str) -> tuple[bool, str]:
    """Validate that a key name is in the allowed set for send_keys.
    Returns (True, "ok") or (False, error_message)."""
    if keys not in ALLOWED_TMUX_KEYS:
        return False, f"key '{keys}' not in allowed set"
    return True, "ok"


# ── Request body limits ──────────────────────────────────────────────────────

MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB
