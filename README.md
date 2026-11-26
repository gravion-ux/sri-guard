<p align="center"><img src="assets/banner.svg" alt="sri-guard banner" width="100%"/></p>

# sri-guard

[![CI](https://github.com/gravion-ux/sri-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gravion-ux/sri-guard/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Subresource Integrity (SRI) checker for HTML pages: finds external scripts and stylesheets whose integrity metadata is missing, malformed, or does not match the actual resource con.**

When a page loads a script or stylesheet from a CDN without an `integrity` attribute, a compromised CDN (or a compromised connection to it) can serve arbitrary code to your visitors. SRI lets the browser verify a cryptographic hash of the resource before using it. sri-guard audits your pages for the common ways that protection is absent or broken — offline by default, using only the Python standard library.

## What it checks

| Code | Severity | Meaning |
| --- | --- | --- |
| `MISSING_INTEGRITY` | high (script) / medium (stylesheet) | Cross-origin resource has no `integrity` attribute |
| `MALFORMED_INTEGRITY` | high (script) / medium (stylesheet) | `integrity` is present but unparseable: unsupported algorithm, invalid base64, or wrong digest length |
| `INTEGRITY_MISMATCH` | high | Resource content (from `--mirror` or `--fetch`) does not match its integrity hash — the browser would block it |
| `MISSING_CROSSORIGIN` | medium | Cross-origin resource has `integrity` but no `crossorigin` attribute, so SRI is not enforced |
| `INLINE_SCRIPT` | info | Inline `<script>` block, which cannot carry SRI |

Same-origin resources are exempt from the missing-integrity rule: relative URLs always count as same-origin, and absolute URLs count as same-origin when they match `--origin` (or the origin of a scanned URL). `sha256`, `sha384`, and `sha512` hashes are verified; when several algorithms are present, the strongest one must match, mirroring browser behaviour.

## Install

```bash
pip install sri-guard
```

Or from a checkout:

```bash
pip install -e .
```

Requires Python 3.11+. No runtime dependencies.

## Usage

Scan files, a directory, or live URLs:

```bash
sri-guard index.html
sri-guard --dir ./dist
sri-guard https://example.com/
python -m sri_guard index.html
```

Tell sri-guard the page origin so first-party absolute URLs are treated as same-origin:

```bash
sri-guard --origin https://example.com dist/index.html
```

Verify hashes against local copies of the CDN files (fully offline). The mirror is searched as `<mirror>/<host>/<path>`, then `<mirror>/<path>`, then `<mirror>/<basename>`:

```bash
sri-guard --mirror ./vendor dist/index.html
```

Or fetch the resources to verify them:

```bash
sri-guard --fetch https://example.com/
```

Machine-readable output and exit codes for CI:

```bash
sri-guard --format json --dir ./dist
```

Exit codes: `0` when no finding reaches the `--fail-on` threshold (`low` by default, so info-only notes pass; use `--strict` to fail on info too), `1` when findings are present, `2` for usage errors.

## Example

Given `index.html`:

```html
<script src="https://cdn.example.com/app.js"></script>
<link rel="stylesheet" href="https://cdn.example.com/site.css">
<script src="/static/local.js"></script>
```

```console
$ sri-guard index.html
sri-guard: scanned 1 source(s)
[HIGH] MISSING_INTEGRITY index.html:1 https://cdn.example.com/app.js - Cross-origin script has no integrity attribute
[MEDIUM] MISSING_INTEGRITY index.html:2 https://cdn.example.com/site.css - Cross-origin stylesheet has no integrity attribute
Summary: 2 finding(s) (1 high, 1 medium)
```

The same-origin `/static/local.js` is not flagged.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

Tests are fully offline: fixture HTML plus mocked fetching.

## License

MIT — see [LICENSE](LICENSE).
