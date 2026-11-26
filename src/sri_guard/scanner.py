"""HTML scanning for Subresource Integrity problems.

The scanner walks ``<script src>`` and ``<link rel="stylesheet" href>``
tags and reports missing, malformed, or mismatching integrity metadata
on cross-origin resources. Relative URLs and resources matching the
page origin (``--origin`` or the scanned URL's origin) are same-origin
and exempt from the missing-integrity rule.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

from .verify import fetch_url, parse_integrity, resolve_mirror, verify_content

Fetcher = Callable[[str], bytes]

_SKIPPABLE_SCHEMES = {"data", "blob", "javascript", "about"}
_DEFAULT_PORTS = {"http": 80, "https": 443}
HTML_SUFFIXES = {".html", ".htm"}


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Resource:
    """An external script or stylesheet referenced by a page."""

    resource_type: str  # "script" or "stylesheet"
    url: str
    integrity: str | None
    crossorigin: str | None
    line: int


@dataclass(frozen=True)
class Finding:
    """A single SRI problem (or informational note) on a page."""

    code: str
    severity: Severity
    message: str
    source: str
    line: int
    url: str | None = None
    resource_type: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": str(self.severity),
            "message": self.message,
            "source": self.source,
            "line": self.line,
            "url": self.url,
            "resource_type": self.resource_type,
        }


class _Collector(HTMLParser):
    """Collect script/stylesheet resources and inline script blocks."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.resources: list[Resource] = []
        self.inline_scripts: list[int] = []  # line numbers
        self._collecting = False
        self._script_line = 0
        self._chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {name.lower(): value for name, value in attrs}
        line = self.getpos()[0]
        if tag == "script":
            src = (attr.get("src") or "").strip()
            if src:
                self.resources.append(
                    Resource(
                        resource_type="script",
                        url=src,
                        integrity=attr.get("integrity"),
                        crossorigin=attr.get("crossorigin"),
                        line=line,
                    )
                )
                self._collecting = False
            else:
                self._collecting = True
                self._script_line = line
                self._chunks = []
        elif tag == "link":
            rel = (attr.get("rel") or "").lower().split()
            href = (attr.get("href") or "").strip()
            if "stylesheet" in rel and href:
                self.resources.append(
                    Resource(
                        resource_type="stylesheet",
                        url=href,
                        integrity=attr.get("integrity"),
                        crossorigin=attr.get("crossorigin"),
                        line=line,
                    )
                )

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self._collecting:
            self._chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._collecting:
            if "".join(self._chunks).strip():
                self.inline_scripts.append(self._script_line)
            self._collecting = False
            self._chunks = []


def normalize_origin(value: str | None) -> str | None:
    """Normalize an origin (``scheme://host[:port]``) or raise ValueError."""
    if value is None:
        return None
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"invalid origin {value!r}: expected e.g. https://example.com")
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    port = parsed.port
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _origin_of(url: str, default_scheme: str = "https") -> str | None:
    parsed = urlparse(url)
    if not parsed.hostname:
        return None
    scheme = (parsed.scheme or default_scheme).lower()
    host = parsed.hostname.lower()
    port = parsed.port
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def is_skippable_url(url: str) -> bool:
    """True for URLs that are not fetchable external resources."""
    stripped = url.strip()
    if not stripped or stripped.startswith("#"):
        return True
    return urlparse(stripped).scheme.lower() in _SKIPPABLE_SCHEMES


def is_cross_origin(url: str, origin: str | None) -> bool:
    """True when ``url`` is cross-origin relative to ``origin``.

    Relative URLs are always same-origin. Without a known origin, every
    absolute or protocol-relative URL counts as cross-origin.
    """
    parsed = urlparse(url.strip())
    if not parsed.netloc:
        return False
    if origin is None:
        return True
    origin_scheme = urlparse(origin).scheme or "https"
    return _origin_of(url, default_scheme=origin_scheme) != normalize_origin(origin)


def _absolute_url(resource_url: str, source: str, origin: str | None) -> str | None:
    if source.startswith(("http://", "https://")):
        return urljoin(source, resource_url)
    if resource_url.startswith("//"):
        scheme = urlparse(origin).scheme if origin else "https"
        return f"{scheme}:{resource_url}"
    parsed = urlparse(resource_url)
    if parsed.scheme in {"http", "https"}:
        return resource_url
    if origin:
        return urljoin(origin + "/", resource_url)
    return None


def _load_content(
    resource: Resource,
    source: str,
    origin: str | None,
    mirror_dir: Path | None,
    fetch: bool,
    fetcher: Fetcher | None,
    base_dir: Path | None,
    timeout: float,
) -> bytes | None:
    """Return resource bytes from the mirror, a local file, or the network."""
    absolute = _absolute_url(resource.url, source, origin)
    if mirror_dir is not None:
        mirrored = resolve_mirror(mirror_dir, absolute or resource.url)
        if mirrored is not None:
            return mirrored.read_bytes()
    parsed = urlparse(resource.url)
    if base_dir is not None and not parsed.netloc and parsed.scheme not in {"http", "https"}:
        local = (base_dir / parsed.path.lstrip("/")).resolve()
        if local.is_file():
            return local.read_bytes()
    if fetch and absolute and absolute.startswith(("http://", "https://")):
        try:
            if fetcher is not None:
                return fetcher(absolute)
            return fetch_url(absolute, timeout=timeout)
        except Exception:
            return None
    return None


def scan_html_text(
    text: str,
    source: str = "<string>",
    origin: str | None = None,
    mirror_dir: Path | None = None,
    fetch: bool = False,
    fetcher: Fetcher | None = None,
    base_dir: Path | None = None,
    timeout: float = 10.0,
) -> list[Finding]:
    """Scan one HTML document (given as text) and return its findings."""
    if origin is not None:
        effective_origin = normalize_origin(origin)
    elif source.startswith(("http://", "https://")):
        effective_origin = normalize_origin(source)
    else:
        effective_origin = None

    collector = _Collector()
    collector.feed(text)
    collector.close()

    findings: list[Finding] = []
    for line in collector.inline_scripts:
        findings.append(
            Finding(
                code="INLINE_SCRIPT",
                severity=Severity.INFO,
                message=(
                    "Inline <script> block cannot carry Subresource Integrity; "
                    "consider moving it to an external file or covering it with CSP"
                ),
                source=source,
                line=line,
                resource_type="script",
            )
        )

    for resource in collector.resources:
        if is_skippable_url(resource.url):
            continue
        cross_origin = is_cross_origin(resource.url, effective_origin)
        script = resource.resource_type == "script"

        if resource.integrity is None:
            if cross_origin:
                findings.append(
                    Finding(
                        code="MISSING_INTEGRITY",
                        severity=Severity.HIGH if script else Severity.MEDIUM,
                        message=(
                            f"Cross-origin {resource.resource_type} has no "
                            "integrity attribute"
                        ),
                        source=source,
                        line=resource.line,
                        url=resource.url,
                        resource_type=resource.resource_type,
                    )
                )
            continue

        tokens, errors = parse_integrity(resource.integrity)
        if errors or not tokens:
            detail = "; ".join(errors) if errors else "no valid integrity token"
            findings.append(
                Finding(
                    code="MALFORMED_INTEGRITY",
                    severity=Severity.HIGH if script else Severity.MEDIUM,
                    message=f"Malformed integrity attribute: {detail}",
                    source=source,
                    line=resource.line,
                    url=resource.url,
                    resource_type=resource.resource_type,
                )
            )
        else:
            content = _load_content(
                resource,
                source,
                effective_origin,
                mirror_dir,
                fetch,
                fetcher,
                base_dir,
                timeout,
            )
            if content is not None and not verify_content(content, resource.integrity):
                findings.append(
                    Finding(
                        code="INTEGRITY_MISMATCH",
                        severity=Severity.HIGH,
                        message=(
                            "Resource content does not match its integrity "
                            "attribute (the browser would block it)"
                        ),
                        source=source,
                        line=resource.line,
                        url=resource.url,
                        resource_type=resource.resource_type,
                    )
                )

        if cross_origin and resource.crossorigin is None:
            findings.append(
                Finding(
                    code="MISSING_CROSSORIGIN",
                    severity=Severity.MEDIUM,
                    message=(
                        "Cross-origin resource with integrity is missing "
                        'crossorigin="anonymous"; SRI is not enforced without CORS mode'
                    ),
                    source=source,
                    line=resource.line,
                    url=resource.url,
                    resource_type=resource.resource_type,
                )
            )

    findings.sort(key=lambda f: (f.line, f.code))
    return findings


def scan_file(
    path: Path,
    origin: str | None = None,
    mirror_dir: Path | None = None,
    fetch: bool = False,
    fetcher: Fetcher | None = None,
    timeout: float = 10.0,
) -> list[Finding]:
    """Scan one HTML file on disk."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return scan_html_text(
        text,
        source=str(path),
        origin=origin,
        mirror_dir=mirror_dir,
        fetch=fetch,
        fetcher=fetcher,
        base_dir=path.parent,
        timeout=timeout,
    )


def scan_url(
    url: str,
    origin: str | None = None,
    mirror_dir: Path | None = None,
    fetch: bool = False,
    fetcher: Fetcher | None = None,
    page_fetcher: Fetcher | None = None,
    timeout: float = 10.0,
) -> list[Finding]:
    """Fetch and scan one HTML page by URL."""
    fetch_page = page_fetcher or fetcher
    if fetch_page is not None:
        raw = fetch_page(url)
    else:
        raw = fetch_url(url, timeout=timeout)
    text = raw.decode("utf-8", errors="replace")
    return scan_html_text(
        text,
        source=url,
        origin=origin,
        mirror_dir=mirror_dir,
        fetch=fetch,
        fetcher=fetcher,
        timeout=timeout,
    )


def collect_html_files(directory: Path) -> list[Path]:
    """Return every ``.html``/``.htm`` file under ``directory``, sorted."""
    return sorted(
        p
        for p in directory.rglob("*")
        if p.is_file() and p.suffix.lower() in HTML_SUFFIXES
    )
