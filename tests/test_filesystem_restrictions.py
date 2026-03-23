"""Unit tests for filesystem path restrictions."""

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from security import is_path_allowed


def test_ssh_keys_blocked():
    assert is_path_allowed(Path("~/.ssh/id_rsa").expanduser()) is False
    assert is_path_allowed(Path("~/.ssh/id_ed25519").expanduser()) is False
    assert is_path_allowed(Path("~/.ssh/known_hosts").expanduser()) is False
    assert is_path_allowed(Path("~/.ssh").expanduser()) is False


def test_gnupg_blocked():
    assert is_path_allowed(Path("~/.gnupg/private-keys-v1.d").expanduser()) is False
    assert is_path_allowed(Path("~/.gnupg/trustdb.gpg").expanduser()) is False


def test_cloud_credentials_blocked():
    assert is_path_allowed(Path("~/.aws/credentials").expanduser()) is False
    assert is_path_allowed(Path("~/.aws/config").expanduser()) is False
    assert is_path_allowed(Path("~/.kube/config").expanduser()) is False
    assert is_path_allowed(Path("~/.config/gcloud/creds.json").expanduser()) is False
    assert is_path_allowed(Path("~/.config/gh/hosts.yml").expanduser()) is False


def test_auth_files_blocked():
    assert is_path_allowed(Path("~/.netrc").expanduser()) is False
    assert is_path_allowed(Path("~/.npmrc").expanduser()) is False
    assert is_path_allowed(Path("~/.docker/config.json").expanduser()) is False


def test_etc_shadow_blocked():
    assert is_path_allowed(Path("/etc/shadow")) is False
    assert is_path_allowed(Path("/etc/sudoers")) is False


def test_etc_ssh_dir_blocked():
    assert is_path_allowed(Path("/etc/ssh/sshd_config")) is False
    assert is_path_allowed(Path("/etc/ssh/ssh_host_rsa_key")) is False


def test_run_secrets_blocked():
    assert is_path_allowed(Path("/run/secrets/db_password")) is False


def test_macos_private_variants_blocked():
    assert is_path_allowed(Path("/private/etc/shadow")) is False
    assert is_path_allowed(Path("/private/etc/sudoers")) is False
    assert is_path_allowed(Path("/private/etc/ssh/sshd_config")) is False


def test_project_files_allowed():
    assert is_path_allowed(Path("~/repo/amux/amux-server.py").expanduser()) is True
    assert is_path_allowed(Path("~/Documents/readme.md").expanduser()) is True


def test_downloads_allowed():
    assert is_path_allowed(Path("~/Downloads/file.zip").expanduser()) is True


def test_tmp_allowed():
    assert is_path_allowed(Path("/tmp/test.txt")) is True


def test_amux_data_dir_allowed():
    assert is_path_allowed(Path("~/.amux/board.json").expanduser()) is True
    assert is_path_allowed(Path("~/.amux/sessions").expanduser()) is True


def test_other_config_dirs_allowed():
    assert is_path_allowed(Path("~/.config/alacritty/alacritty.toml").expanduser()) is True
    assert is_path_allowed(Path("~/.config/wezterm/wezterm.lua").expanduser()) is True


def test_etc_hosts_allowed():
    assert is_path_allowed(Path("/etc/hosts")) is True


def test_traversal_to_ssh_blocked():
    assert is_path_allowed(Path("~/.config/gh/../../.ssh/id_rsa").expanduser()) is False


def test_traversal_from_safe_to_sensitive():
    assert is_path_allowed(Path("~/Documents/../.ssh/id_rsa").expanduser()) is False


def test_deeply_nested_sensitive_path_blocked():
    assert is_path_allowed(Path("~/.ssh/keys/backup/old_key").expanduser()) is False
    assert is_path_allowed(Path("~/.aws/sso/cache/token.json").expanduser()) is False


def test_auth_token_file_blocked():
    token_file = Path("~/.amux/auth_token").expanduser()
    assert is_path_allowed(token_file, auth_token_file=token_file) is False


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  PASS: {t.__name__}")
    print(f"\nAll {len(tests)} filesystem restriction tests passed!")
