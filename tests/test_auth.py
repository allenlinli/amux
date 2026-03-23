"""Unit tests for bearer token authentication."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from security import load_or_create_auth_token, check_auth

TOKEN = "test-secret-token-abc123"


def test_api_rejects_without_token():
    assert check_auth(TOKEN, "GET", "/api/sessions") is False
    assert check_auth(TOKEN, "POST", "/api/board/items") is False
    assert check_auth(TOKEN, "DELETE", "/api/notes/test.md") is False


def test_proxy_rejects_without_token():
    assert check_auth(TOKEN, "GET", "/proxy/3000/") is False
    assert check_auth(TOKEN, "POST", "/proxy/8080/api") is False


def test_correct_token_accepted():
    assert check_auth(TOKEN, "GET", "/api/sessions", f"Bearer {TOKEN}") is True
    assert check_auth(TOKEN, "POST", "/api/board/items", f"Bearer {TOKEN}") is True
    assert check_auth(TOKEN, "GET", "/proxy/3000/", f"Bearer {TOKEN}") is True


def test_wrong_token_rejected():
    assert check_auth(TOKEN, "GET", "/api/sessions", "Bearer wrong") is False
    assert check_auth(TOKEN, "GET", "/api/sessions", "Bearer ") is False
    assert check_auth(TOKEN, "GET", "/api/sessions", TOKEN) is False  # missing "Bearer "


def test_public_paths_bypass_auth():
    for path in ["/", "/manifest.json", "/sw.js", "/icon.svg", "/icon.png",
                 "/release-notes", "/api/release-notes"]:
        assert check_auth(TOKEN, "GET", path) is True, f"{path} should be public"


def test_share_links_bypass_auth():
    assert check_auth(TOKEN, "GET", "/s/abc123") is True
    assert check_auth(TOKEN, "GET", "/api/share/xyz") is True
    assert check_auth(TOKEN, "GET", "/invite/token123") is True


def test_static_asset_gets_bypass_auth():
    assert check_auth(TOKEN, "GET", "/styles.css") is True
    assert check_auth(TOKEN, "GET", "/app.js") is True
    assert check_auth(TOKEN, "GET", "/favicon.ico") is True


def test_static_asset_post_requires_auth():
    assert check_auth(TOKEN, "POST", "/styles.css") is False


def test_ca_requires_auth():
    assert check_auth(TOKEN, "GET", "/ca") is False


def test_sse_query_param_fallback():
    url = f"/api/sessions/stream?_token={TOKEN}"
    assert check_auth(TOKEN, "GET", "/api/sessions/stream", "", url) is True


def test_sse_wrong_query_param_rejected():
    url = "/api/sessions/stream?_token=wrong"
    assert check_auth(TOKEN, "GET", "/api/sessions/stream", "", url) is False


def test_disabled_auth_allows_everything():
    assert check_auth("", "GET", "/api/sessions") is True
    assert check_auth("", "POST", "/api/board/items") is True
    assert check_auth("", "GET", "/proxy/3000/") is True


def test_token_file_creation():
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "auth_token"
        token = load_or_create_auth_token(token_file, Path(tmpdir))
        assert len(token) > 20
        assert token_file.exists()
        assert token_file.read_text().strip() == token
        perms = oct(token_file.stat().st_mode)[-3:]
        assert perms == "600", f"Expected 600, got {perms}"


def test_token_file_reuse():
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "auth_token"
        token1 = load_or_create_auth_token(token_file, Path(tmpdir))
        token2 = load_or_create_auth_token(token_file, Path(tmpdir))
        assert token1 == token2


def test_env_token_override():
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "auth_token"
        os.environ["AMUX_AUTH_TOKEN"] = "custom-token"
        try:
            token = load_or_create_auth_token(token_file, Path(tmpdir))
            assert token == "custom-token"
            assert not token_file.exists()
        finally:
            del os.environ["AMUX_AUTH_TOKEN"]


def test_env_token_none_disables():
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "auth_token"
        os.environ["AMUX_AUTH_TOKEN"] = "none"
        try:
            token = load_or_create_auth_token(token_file, Path(tmpdir))
            assert token == ""
        finally:
            del os.environ["AMUX_AUTH_TOKEN"]


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  PASS: {t.__name__}")
    print(f"\nAll {len(tests)} auth tests passed!")
