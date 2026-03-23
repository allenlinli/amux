"""Unit tests for CORS origin validation."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from security import is_origin_allowed


def test_localhost_allowed():
    assert is_origin_allowed("http://localhost:8822") is True
    assert is_origin_allowed("https://localhost:8822") is True
    assert is_origin_allowed("http://localhost") is True


def test_loopback_ip_allowed():
    assert is_origin_allowed("http://127.0.0.1:8822") is True
    assert is_origin_allowed("https://127.0.0.1:8822") is True


def test_lan_ip_allowed():
    assert is_origin_allowed("http://192.168.1.100:8822", "192.168.1.100") is True
    assert is_origin_allowed("http://10.0.0.5:8822", "10.0.0.5") is True


def test_tailscale_hostname_allowed():
    assert is_origin_allowed("https://nuc.tail37bf06.ts.net:8822") is True
    assert is_origin_allowed("https://myhost.ts.net") is True
    assert is_origin_allowed("http://anything.ts.net:3000") is True


def test_external_domains_blocked():
    assert is_origin_allowed("https://evil.com") is False
    assert is_origin_allowed("https://google.com") is False
    assert is_origin_allowed("http://malicious-site.com:8822") is False


def test_similar_looking_domains_blocked():
    assert is_origin_allowed("http://localhost.evil.com") is False
    assert is_origin_allowed("http://fake-ts.net") is False
    assert is_origin_allowed("http://not-a.ts.net.evil.com") is False


def test_different_lan_ip_blocked():
    assert is_origin_allowed("http://192.168.1.200:8822", "192.168.1.100") is False
    assert is_origin_allowed("http://10.0.0.99:8822", "10.0.0.5") is False


def test_empty_origin_blocked():
    assert is_origin_allowed("") is False


def test_ts_net_suffix_only():
    assert is_origin_allowed("http://ts.net") is False
    assert is_origin_allowed("http://evil-ts.net") is False


def test_different_ports_same_host_allowed():
    assert is_origin_allowed("http://localhost:3000") is True
    assert is_origin_allowed("http://localhost:9999") is True


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  PASS: {t.__name__}")
    print(f"\nAll {len(tests)} CORS tests passed!")
