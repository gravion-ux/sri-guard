"""Unit tests for integrity parsing and verification (fully offline)."""

from __future__ import annotations

import base64
import hashlib

import pytest

from sri_guard.verify import (
    compute_integrity,
    parse_integrity,
    resolve_mirror,
    verify_content,
)

CONTENT = b"console.log('hello');\n"


def _token(algorithm: str, content: bytes = CONTENT) -> str:
    digest = base64.b64encode(hashlib.new(algorithm, content).digest()).decode("ascii")
    return f"{algorithm}-{digest}"


@pytest.mark.parametrize("algorithm", ["sha256", "sha384", "sha512"])
def test_verify_accepts_each_supported_algorithm(algorithm: str) -> None:
    assert verify_content(CONTENT, _token(algorithm)) is True
    assert compute_integrity(CONTENT, algorithm) == _token(algorithm)


def test_verify_rejects_tampered_content() -> None:
    assert verify_content(b"evil();", _token("sha384")) is False


def test_strongest_algorithm_wins() -> None:
    good_weak = _token("sha256")
    bad_strong = _token("sha384", b"other content")
    assert verify_content(CONTENT, f"{good_weak} {bad_strong}") is False
    good_strong = _token("sha384")
    assert verify_content(CONTENT, f"{good_weak} {good_strong}") is True


def test_parse_integrity_flags_malformed_values() -> None:
    tokens, errors = parse_integrity("sha384-not!base64")
    assert tokens == []
    assert errors

    tokens, errors = parse_integrity("md5-AAAA")
    assert tokens == []
    assert any("unsupported" in e for e in errors)

    short = base64.b64encode(b"short").decode("ascii")
    tokens, errors = parse_integrity(f"sha256-{short}")
    assert tokens == []
    assert any("bytes" in e for e in errors)

    tokens, errors = parse_integrity("")
    assert tokens == []
    assert errors

    tokens, errors = parse_integrity(None)
    assert tokens == []
    assert errors == []


def test_parse_integrity_accepts_options_suffix() -> None:
    tokens, errors = parse_integrity(_token("sha384") + "?foo=bar")
    assert errors == []
    assert len(tokens) == 1
    assert tokens[0].options == "foo=bar"


def test_resolve_mirror_prefers_host_path_then_basename(tmp_path) -> None:
    host_file = tmp_path / "cdn.example.com" / "lib" / "app.js"
    host_file.parent.mkdir(parents=True)
    host_file.write_bytes(b"host copy")
    (tmp_path / "app.js").write_bytes(b"basename copy")

    found = resolve_mirror(tmp_path, "https://cdn.example.com/lib/app.js")
    assert found == host_file

    assert resolve_mirror(tmp_path, "https://other.example.com/app.js") == tmp_path / "app.js"
    assert resolve_mirror(tmp_path, "https://other.example.com/missing.js") is None
