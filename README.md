# hardening-audit

Audit HTTPS endpoints for web-hardening weaknesses from the command line.

Checks, per URL: reachability, TLS certificate posture, missing/invalid
security headers (HSTS, `X-Content-Type-Options`, `Referrer-Policy`, CSP
`frame-ancestors` / `X-Frame-Options`), insecure cookie flags, and mixed
content references. Pure Python, **stdlib only**; no third-party dependencies.

## Install
No dependencies. Copy the file and run it, or install with pip:

```
pip install .
hardening-audit https://example.com
```

## Usage
```
# Human report
python hardening_audit.py https://example.com https://myservice.com

# Machine-readable (CI / scripting)
python hardening_audit.py --json https://example.com

# Options
  --timeout <s>     per-request timeout (default 15)
  --insecure        skip TLS certificate verification (not recommended)
  --max-mixed <n>   cap mixed-content findings per URL (default 5)
  --verbose
```

## Reports (the deliverable)
`report.py` renders an audit report into a product-grade, one-page ranked
Markdown document with per-finding remediation, which is the shape of the
paid single-site audit deliverable. Pure stdlib, ASCII-only output.

```
# Audit, then render the human-facing report
python hardening_audit.py --json https://yoursite.com > audit.json
python report.py audit.json -o report.md
```

```
python report.py audit.json          # Markdown to stdout
```

Verdict: `FAIL` (any critical) / `NEEDS ATTENTION` (any high) /
`PASS (advisories)` / `PASS`. Render exit codes: `0` rendered, `2` malformed
input. A real rendered sample from a live weak-endpoint audit is shipped at
`examples/sample-report.md`.

## Exit codes (CI-friendly)
- `0` no critical or high findings
- `1` at least one **high** finding
- `2` at least one **critical** finding (e.g. host unreachable)

Medium and low findings never fail the pipeline.

## Self-test
```
python selftest.py        # exercises the tool against local HTTPS fixtures
```

## Adoption

### GitHub Actions (CI gating)
Add to any workflow to fail the build on weak hardening posture:

```
name: web-hardening
on: [push]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: greg-holman/hardening-audit@main
        with:
          url: 'https://example.com'
          fail-on: high
```

`fail-on` accepts `none`, `low`, `medium`, `high` (default), or `critical`.
The step fails with annotations when any finding meets the threshold and
exposes `passed` / `summary` outputs for downstream logic.

### Command line
```
pip install hardening-audit        # if published
# or run from a checkout:
python hardening_audit.py https://example.com
```

### Report rendering
```
python hardening_audit.py --json https://example.com > audit.json
python report.py audit.json -o report.md
```

## Notes
This tool reports what it observes on the wire. It does not make changes, does
not send data anywhere, and prints no secrets.
