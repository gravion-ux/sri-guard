"""Text and JSON report rendering for sri-guard."""

from __future__ import annotations

import json
from collections import Counter

from . import __version__
from .scanner import SEVERITY_ORDER, Finding


def summarize(findings: list[Finding]) -> dict[str, object]:
    """Return total, per-severity, and per-code counts for findings."""
    by_severity = Counter(str(f.severity) for f in findings)
    by_code = Counter(f.code for f in findings)
    return {
        "total": len(findings),
        "by_severity": dict(sorted(by_severity.items())),
        "by_code": dict(sorted(by_code.items())),
    }


def render_text(findings: list[Finding], sources: list[str]) -> str:
    """Render findings as a human-readable text report."""
    lines = [f"sri-guard: scanned {len(sources)} source(s)"]
    if not findings:
        lines.append("No findings. All checked resources passed.")
        return "\n".join(lines) + "\n"
    for finding in findings:
        location = f"{finding.source}:{finding.line}"
        target = f" {finding.url}" if finding.url else ""
        lines.append(
            f"[{str(finding.severity).upper()}] {finding.code} "
            f"{location}{target} - {finding.message}"
        )
    summary = summarize(findings)
    by_severity = summary["by_severity"]
    assert isinstance(by_severity, dict)
    breakdown = ", ".join(f"{count} {name}" for name, count in by_severity.items())
    lines.append(f"Summary: {summary['total']} finding(s) ({breakdown})")
    return "\n".join(lines) + "\n"


def render_json(findings: list[Finding], sources: list[str]) -> str:
    """Render findings as a JSON report."""
    payload = {
        "tool": "sri-guard",
        "version": __version__,
        "sources": sources,
        "summary": summarize(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2) + "\n"


def exit_code_for(findings: list[Finding], fail_on: str = "low") -> int:
    """Return 1 when any finding is at or above ``fail_on``, else 0."""
    threshold = SEVERITY_ORDER[fail_on]
    for finding in findings:
        if SEVERITY_ORDER[str(finding.severity)] >= threshold:
            return 1
    return 0
