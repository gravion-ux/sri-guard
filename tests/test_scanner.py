"""Scanner tests over fixture HTML (fully offline; fetch is mocked)."""

from __future__ import annotations

import base64
import hashlib

from sri_guard.scanner import Severity, scan_file, scan_html_text, scan_url

SCRIPT_BODY = b"console.log('lib');\n"
STYLE_BODY = b"body { color: red; }\n"


def _integrity(content: bytes, algorithm: str = "sha384") -> str:
    digest = base64.b64encode(hashlib.new(algorithm, content).digest()).decode("ascii")
    return f"{algorithm}-{digest}"


def _codes(findings) -> list[str]:
    return [f.code for f in findings]


def test_missing_integrity_on_cross_origin_script_is_high() -> None:
    html = '<script src="https://cdn.example.com/app.js"></script>'
    findings = scan_html_text(html)
    assert _codes(findings) == ["MISSING_INTEGRITY"]
    assert findings[0].severity == Severity.HIGH
    assert findings[0].resource_type == "script"


def test_missing_integrity_on_stylesheet_is_medium() -> None:
    html = '<link rel="stylesheet" href="https://cdn.example.com/site.css">'
    findings = scan_html_text(html)
    assert _codes(findings) == ["MISSING_INTEGRITY"]
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].resource_type == "stylesheet"


def test_missing_integrity_on_modulepreload_is_high() -> None:
    html = '<link rel="modulepreload" href="https://cdn.example.com/app.mjs">'
    findings = scan_html_text(html)
    assert _codes(findings) == ["MISSING_INTEGRITY"]
    assert findings[0].severity == Severity.HIGH
    assert findings[0].resource_type == "modulepreload"


def test_valid_modulepreload_integrity_with_crossorigin_is_clean() -> None:
    html = (
        f'<link rel="modulepreload" href="https://cdn.example.com/app.mjs" '
        f'integrity="{_integrity(SCRIPT_BODY)}" crossorigin="anonymous">'
    )
    assert scan_html_text(html) == []


def test_relative_urls_are_same_origin_exempt() -> None:
    html = (
        '<script src="/static/app.js"></script>'
        '<script src="js/local.js"></script>'
        '<link rel="stylesheet" href="./site.css">'
    )
    assert scan_html_text(html) == []


def test_origin_match_is_exempt_and_mismatch_is_flagged() -> None:
    html = '<script src="https://example.com/app.js"></script>'
    assert scan_html_text(html, origin="https://example.com") == []

    findings = scan_html_text(html, origin="https://other.example.com")
    assert _codes(findings) == ["MISSING_INTEGRITY"]


def test_protocol_relative_url_is_cross_origin() -> None:
    html = '<script src="//cdn.example.com/app.js"></script>'
    findings = scan_html_text(html, origin="https://example.com")
    assert _codes(findings) == ["MISSING_INTEGRITY"]


def test_valid_integrity_with_crossorigin_is_clean() -> None:
    html = (
        f'<script src="https://cdn.example.com/app.js" '
        f'integrity="{_integrity(SCRIPT_BODY)}" crossorigin="anonymous"></script>'
    )
    assert scan_html_text(html) == []


def test_missing_crossorigin_with_integrity_is_flagged() -> None:
    html = (
        f'<script src="https://cdn.example.com/app.js" '
        f'integrity="{_integrity(SCRIPT_BODY)}"></script>'
    )
    findings = scan_html_text(html)
    assert _codes(findings) == ["MISSING_CROSSORIGIN"]
    assert findings[0].severity == Severity.MEDIUM


def test_malformed_integrity_is_flagged() -> None:
    html = (
        '<script src="https://cdn.example.com/app.js" '
        'integrity="sha384-!!!not-base64!!!" crossorigin="anonymous"></script>'
    )
    findings = scan_html_text(html)
    assert _codes(findings) == ["MALFORMED_INTEGRITY"]


def test_mirror_verification_match_and_mismatch(tmp_path) -> None:
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    (mirror / "app.js").write_bytes(SCRIPT_BODY)

    good = (
        f'<script src="https://cdn.example.com/app.js" '
        f'integrity="{_integrity(SCRIPT_BODY)}" crossorigin="anonymous"></script>'
    )
    assert scan_html_text(good, mirror_dir=mirror) == []

    bad = (
        f'<script src="https://cdn.example.com/app.js" '
        f'integrity="{_integrity(b"different")}" crossorigin="anonymous"></script>'
    )
    findings = scan_html_text(bad, mirror_dir=mirror)
    assert _codes(findings) == ["INTEGRITY_MISMATCH"]
    assert findings[0].severity == Severity.HIGH


def test_fetched_content_verification_with_mock() -> None:
    calls: list[str] = []

    def fake_fetch(url: str) -> bytes:
        calls.append(url)
        return STYLE_BODY

    html = (
        f'<link rel="stylesheet" href="https://cdn.example.com/site.css" '
        f'integrity="{_integrity(SCRIPT_BODY)}" crossorigin="anonymous">'
    )
    findings = scan_html_text(html, fetch=True, fetcher=fake_fetch)
    assert calls == ["https://cdn.example.com/site.css"]
    assert _codes(findings) == ["INTEGRITY_MISMATCH"]

    # Without --fetch the same page cannot be verified and stays clean.
    assert scan_html_text(html, fetch=False, fetcher=fake_fetch) == []


def test_local_relative_resource_is_verified_against_disk(tmp_path) -> None:
    (tmp_path / "app.js").write_bytes(SCRIPT_BODY)
    page = tmp_path / "index.html"
    page.write_text(
        f'<script src="app.js" integrity="{_integrity(b"stale")}"></script>',
        encoding="utf-8",
    )
    findings = scan_file(page)
    assert _codes(findings) == ["INTEGRITY_MISMATCH"]


def test_inline_script_is_info() -> None:
    html = "<script>console.log('inline');</script>"
    findings = scan_html_text(html)
    assert _codes(findings) == ["INLINE_SCRIPT"]
    assert findings[0].severity == Severity.INFO


def test_data_and_fragment_urls_are_ignored() -> None:
    html = (
        '<script src="data:text/javascript,alert(1)"></script>'
        '<link rel="stylesheet" href="#theme">'
    )
    assert scan_html_text(html) == []


def test_scan_url_with_mocked_page_fetch() -> None:
    page = (
        b"<html><head>"
        b'<script src="https://example.com/same.js"></script>'
        b'<script src="https://cdn.example.com/cross.js"></script>'
        b"</head></html>"
    )
    findings = scan_url("https://example.com/index.html", page_fetcher=lambda url: page)
    # The same-origin script is exempt; only the CDN script is flagged.
    assert _codes(findings) == ["MISSING_INTEGRITY"]
    assert findings[0].url == "https://cdn.example.com/cross.js"
    assert findings[0].source == "https://example.com/index.html"
