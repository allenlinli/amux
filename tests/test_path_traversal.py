"""Unit tests for notes API path traversal protection."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from security import safe_note_path


def test_simple_note():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        result = safe_note_path("hello.md", base)
        assert result is not None
        assert result == (base / "hello.md").resolve()


def test_nested_note():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        result = safe_note_path("folder/note.md", base)
        assert result is not None
        assert str(result).startswith(str(base.resolve()))


def test_deeply_nested_note():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = safe_note_path("a/b/c/deep.md", Path(tmpdir))
        assert result is not None


def test_basic_traversal_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert safe_note_path("../../../etc/passwd", Path(tmpdir)) is None


def test_dot_dot_in_middle_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert safe_note_path("notes/../../../etc/shadow", Path(tmpdir)) is None


def test_double_dot_dot_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert safe_note_path("../../.ssh/id_rsa", Path(tmpdir)) is None


def test_traversal_to_parent_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert safe_note_path("../sibling_file", Path(tmpdir)) is None


def test_traversal_with_trailing_slash():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert safe_note_path("../", Path(tmpdir)) is None


def test_absolute_path_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert safe_note_path("/etc/passwd", Path(tmpdir)) is None


def test_absolute_home_path_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert safe_note_path("/home/user/.ssh/id_rsa", Path(tmpdir)) is None


def test_empty_string_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert safe_note_path("", Path(tmpdir)) is None


def test_just_dots_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert safe_note_path("..", Path(tmpdir)) is None


def test_symlink_escape_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir) / "notes"
        base.mkdir()
        link = base / "escape"
        link.symlink_to("/tmp")
        result = safe_note_path("escape/some_file", base)
        assert result is None, "Symlink escape should be blocked"


def test_trash_valid_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        trash = Path(tmpdir) / ".trash"
        trash.mkdir()
        result = safe_note_path("deleted-note.md", trash)
        assert result is not None
        assert str(result).startswith(str(trash.resolve()))


def test_trash_traversal_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        trash = Path(tmpdir) / ".trash"
        trash.mkdir()
        assert safe_note_path("../../etc/passwd", trash) is None


def test_trash_to_notes_traversal_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        trash = Path(tmpdir) / ".trash"
        trash.mkdir()
        assert safe_note_path("../secret.md", trash) is None


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  PASS: {t.__name__}")
    print(f"\nAll {len(tests)} path traversal tests passed!")
