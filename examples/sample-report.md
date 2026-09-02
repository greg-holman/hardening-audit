# Web Hardening Audit Report

Date: 2026-08-29 19:53
Scope: 1 URL(s)
Verdict: NEEDS ATTENTION
Source: hardening-audit

Findings: high 4

## https://example.com/
Reachability: final status 200 (final URL https://example.com/)
TLS: issuer CN Cloudflare TLS Issuing ECC CA 3; expires Oct 27 22:17:21 2026 GMT

### Findings

| Severity | Category | Detail | Remediation |
| --- | --- | --- | --- |
| high | headers | MISSING Referrer-Policy | Add 'Referrer-Policy: same-origin' (nginx 'add_header Referrer-Policy "same-origin" always;'). |
| high | headers | MISSING Strict-Transport-Security | Add the header; example: nginx 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' / Cloudflare: SSL/TLS -> HTTPS settings -> Strict Transport Security: On. |
| high | headers | MISSING clickjacking protection (no X-Frame-Options or CSP frame-ancestors) | Add clickjacking protection: 'X-Frame-Options: SAMEORIGIN' or CSP 'frame-ancestors self' (nginx 'add_header X-Frame-Options "SAMEORIGIN" always;' / 'add_header Content-Security-Policy "frame-ancestors 'self'" always;'). |
| high | headers | MISSING or invalid X-Content-Type-Options (expected nosniff) | Add 'X-Content-Type-Options: nosniff' (nginx 'add_header X-Content-Type-Options "nosniff" always;'). |


*This report describes wire-level observations at the time of audit only; it does not modify anything.*
