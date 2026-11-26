"""Integrity parsing and content verification for sri-guard.

Only the Python standard library is used. The verification follows the
Subresource Integrity model: an ``integrity`` attribute holds one or more
space-separated ``<algorithm>-<base64 digest>`` tokens (optionally followed
by ``?options``), and when several algorithms are present the strongest
one is the one that must match.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

ALGORITHMS: dict[str, int] = {"sha256": 32, "sha384": 48, "sha512": 64}
_STRENGTH: dict[str, int] = {"sha256": 1, "sha384": 2, "sha512": 3}

MAX_FETCH_BYTES = 10_000_000
_USER_AGENT = "sri-guard/0.1.0 (+https://github.com/gravion-ux/sri-guard)"


@dataclass(frozen=True)
class IntegrityToken:
    """A single valid ``algorithm-digest`` token from an integrity value."""

    algorithm: str
    digest_b64: str
    options: str | None = None

    @property
    def strength(self) -> int:
        return _STRENGTH[self.algorithm]


def parse_integrity(value: str | None) -> tuple[list[IntegrityToken], list[str]]:
    """Parse an integrity attribute value.

    Returns ``(tokens, errors)``. ``tokens`` holds every well-formed token;
    ``errors`` describes each malformed token (unsupported algorithm, bad
    base64, or a digest whose length does not match the algorithm).
    A missing attribute (``None``) yields no tokens and no errors; an
    empty attribute is an error.
    """
    if value is None:
        return [], []
    if not value.strip():
        return [], ["integrity attribute is empty"]

    tokens: list[IntegrityToken] = []
    errors: list[str] = []
    for raw in value.split():
        main, sep, options = raw.partition("?")
        algorithm, dash, digest = main.partition("-")
        algorithm = algorithm.lower()
        if not dash or not digest:
            errors.append(f"token {raw!r} is not in '<algorithm>-<digest>' form")
            continue
        if algorithm not in ALGORITHMS:
            errors.append(f"unsupported integrity algorithm {algorithm!r} in {raw!r}")
            continue
        try:
            decoded = base64.b64decode(digest, validate=True)
        except (binascii.Error, ValueError):
            errors.append(f"digest in {raw!r} is not valid base64")
            continue
        expected = ALGORITHMS[algorithm]
        if len(decoded) != expected:
            errors.append(
                f"{algorithm} digest in {raw!r} decodes to {len(decoded)} bytes, "
                f"expected {expected}"
            )
            continue
        tokens.append(
            IntegrityToken(
                algorithm=algorithm,
                digest_b64=digest,
                options=options if sep else None,
            )
        )
    return tokens, errors


def compute_digest_b64(content: bytes, algorithm: str) -> str:
    """Return the base64 digest of ``content`` under ``algorithm``."""
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {algorithm!r}")
    return base64.b64encode(hashlib.new(algorithm, content).digest()).decode("ascii")


def compute_integrity(content: bytes, algorithm: str = "sha384") -> str:
    """Return a full integrity token (``<algorithm>-<digest>``) for content."""
    return f"{algorithm}-{compute_digest_b64(content, algorithm)}"


def verify_content(content: bytes, value: str | None) -> bool:
    """Return True when ``content`` matches the integrity value.

    The strongest algorithm among the valid tokens is authoritative,
    mirroring browser behaviour: a matching weaker hash does not rescue
    a mismatching stronger one.
    """
    tokens, _errors = parse_integrity(value)
    if not tokens:
        return False
    strongest = max(token.strength for token in tokens)
    for token in tokens:
        if token.strength != strongest:
            continue
        actual = compute_digest_b64(content, token.algorithm)
        if hmac.compare_digest(actual, token.digest_b64):
            return True
    return False


def fetch_url(url: str, timeout: float = 10.0, max_bytes: int = MAX_FETCH_BYTES) -> bytes:
    """Fetch ``url`` over HTTP(S) and return its bytes (size-capped)."""
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"resource at {url} exceeds {max_bytes} bytes")
    return data


def resolve_mirror(mirror_dir: Path, url: str) -> Path | None:
    """Find a mirrored local copy of ``url`` under ``mirror_dir``.

    Candidates are tried in order: ``<mirror>/<host>/<path>``,
    ``<mirror>/<path>``, then ``<mirror>/<basename>``.
    """
    parsed = urlparse(url)
    path = parsed.path.lstrip("/")
    candidates: list[Path] = []
    if parsed.hostname:
        candidates.append(mirror_dir / parsed.hostname / path)
    if path:
        candidates.append(mirror_dir / path)
    basename = Path(parsed.path).name
    if basename:
        candidates.append(mirror_dir / basename)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None
