"""CLI tests: exit codes, JSON output, and directory scanning (offline)."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from sri_guard.cli import main

CLEAN_HTML = '<script src="/static/app.js"></script>\n'
DIRTY_HTML = '<script src="https://cdn.example.com/app.js"></script>\n'
INLINE_HTML = "<script>console.log('inline');</script>\n"


def _write(path, content: str) -> str:
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_cli_clean_file_exits_zero(tmp_path, capsys) -> None:
    page = _write(tmp_path / "index.html", CLEAN_HTML)
    assert main([page]) == 0
    assert "No findings" in capsys.readouterr().out


def test_cli_findings_exit_one(tmp_path, capsys) -> None:
    page = _write(tmp_path / "index.html", DIRTY_HTML)
    assert main([page]) == 1
    out = capsys.readouterr().out
    assert "MISSING_INTEGRITY" in out
    assert "[HIGH]" in out


def test_cli_info_only_passes_unless_strict(tmp_path, capsys) -> None:
    page = _write(tmp_path / "index.html", INLINE_HTML)
    assert main([page]) == 0
    capsys.readouterr()
    assert main([page, "--strict"]) == 1


def test_cli_usage_errors_exit_two(tmp_path) -> None:
    with pytest.raises(SystemExit) as no_args:
        main([])
    assert no_args.value.code == 2

    with pytest.raises(SystemExit) as missing:
        main([str(tmp_path / "does-not-exist.html")])
    assert missing.value.code == 2

    page = _write(tmp_path / "index.html", CLEAN_HTML)
    with pytest.raises(SystemExit) as bad_origin:
        main([page, "--origin", "not-a-url"])
    assert bad_origin.value.code == 2


def test_cli_json_report(tmp_path, capsys) -> None:
    page = _write(tmp_path / "index.html", DIRTY_HTML)
    assert main([page, "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "sri-guard"
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["by_code"] == {"MISSING_INTEGRITY": 1}
    finding = payload["findings"][0]
    assert finding["severity"] == "high"
    assert finding["url"] == "https://cdn.example.com/app.js"
    assert finding["line"] == 1


def test_cli_dir_scan_is_recursive(tmp_path, capsys) -> None:
    site = tmp_path / "site"
    (site / "nested").mkdir(parents=True)
    _write(site / "index.html", CLEAN_HTML)
    _write(site / "nested" / "page.htm", DIRTY_HTML)
    _write(site / "notes.txt", DIRTY_HTML)  # not HTML: must be ignored

    assert main(["--dir", str(site)]) == 1
    out = capsys.readouterr().out
    assert "scanned 2 source(s)" in out
    assert out.count("MISSING_INTEGRITY") == 1


def test_cli_mirror_mismatch_exits_one(tmp_path, capsys) -> None:
    body = b"console.log('real');\n"
    digest = base64.b64encode(hashlib.sha384(b"expected").digest()).decode("ascii")
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    (mirror / "app.js").write_bytes(body)
    page = _write(
        tmp_path / "index.html",
        f'<script src="https://cdn.example.com/app.js" '
        f'integrity="sha384-{digest}" crossorigin="anonymous"></script>\n',
    )
    assert main([page, "--mirror", str(mirror)]) == 1
    assert "INTEGRITY_MISMATCH" in capsys.readouterr().out


def test_cli_output_file(tmp_path, capsys) -> None:
    page = _write(tmp_path / "index.html", DIRTY_HTML)
    report = tmp_path / "report.json"
    assert main([page, "--json", "-o", str(report)]) == 1
    assert capsys.readouterr().out == ""
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == 1
