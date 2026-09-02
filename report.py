import sys
import json
import os
from datetime import datetime, timezone


SEVERITIES = ("critical", "high", "medium", "low")


def sanitize(text):
    """Replace non-printable-ASCII characters with question marks."""
    if text is None:
        text = ""
    text = str(text)
    return "".join(c if c in "\n\t" or 0x20 <= ord(c) <= 0x7E else "?"
                   for c in text)


def load_report(path):
    """Load and validate a JSON audit report."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError, UnicodeError):
        return None
    if not isinstance(document, dict) or not isinstance(
            document.get("results"), list):
        return None
    return document


def verdict(findings_all):
    """Return the report verdict for a collection of findings."""
    present = {str(f.get("severity", "")).lower()
               for f in findings_all if isinstance(f, dict)}
    if "critical" in present:
        return "FAIL"
    if "high" in present:
        return "NEEDS ATTENTION"
    if present.intersection(("medium", "low")):
        return "PASS (advisories)"
    return "PASS"


def counts_summary(all):
    """Format the severity counts for a collection of findings."""
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in all:
        if isinstance(finding, dict):
            severity = str(finding.get("severity", "")).lower()
            if severity in counts:
                counts[severity] += 1
    parts = [f"{severity} {counts[severity]}"
             for severity in SEVERITIES if counts[severity]]
    return "Findings: " + (", ".join(parts) if parts else "none")


def remediation(category, detail):
    """Select the first matching remediation for a finding."""
    category = str(category or "").lower()
    detail = str(detail or "").lower()

    if category == "reachability":
        return ("Verify DNS resolution, host availability, and certificate "
                "chain for this endpoint.")
    if category == "tls":
        if "expired" in detail:
            return ("Renew the TLS certificate; add an expiry alerting window "
                    "(e.g. 14 days) to your rotation process.")
        if "expir" in detail:
            return ("Certificate expiry is near; schedule renewal before it "
                    "lapses.")
        return "Review certificate issuance and chain configuration."
    if category == "headers":
        if "strict-transport-security" in detail and (
                "includesubdomains" in detail or "preload" in detail):
            return ("Harden the existing HSTS header to include "
                    "'max-age=63072000; includeSubDomains; preload' "
                    "(extend the existing add_header directive).")
        if "strict-transport-security" in detail and "max-age" in detail:
            return ("The HSTS header is present but incomplete; add max-age "
                    "(e.g. 'max-age=31536000; includeSubDomains').")
        if "strict-transport-security" in detail:
            return ("Add the header; example: nginx 'add_header "
                    "Strict-Transport-Security \"max-age=31536000; "
                    "includeSubDomains\" always;' / Cloudflare: SSL/TLS -> "
                    "HTTPS settings -> Strict Transport Security: On.")
        if "x-content-type-options" in detail:
            return ("Add 'X-Content-Type-Options: nosniff' (nginx "
                    "'add_header X-Content-Type-Options \"nosniff\" always;').")
        if "referrer-policy" in detail:
            return ("Add 'Referrer-Policy: same-origin' (nginx "
                    "'add_header Referrer-Policy \"same-origin\" always;').")
        if "frame-ancestors" in detail or "x-frame-options" in detail:
            return ("Add clickjacking protection: 'X-Frame-Options: SAMEORIGIN' "
                    "or CSP 'frame-ancestors self' (nginx 'add_header "
                    "X-Frame-Options \"SAMEORIGIN\" always;' / 'add_header "
                    "Content-Security-Policy \"frame-ancestors 'self'\" "
                    "always;').")
        if "unsafe-inline" in detail or "unsafe-eval" in detail:
            return ("Tighten the Content-Security-Policy: replace "
                    "'unsafe-inline'/'unsafe-eval' with nonce- or "
                    "hash-based script allowances where possible.")
        if "server response header" in detail:
            return ("Suppress or genericize the Server header so it stops "
                    "disclosing the web server technology (e.g. nginx: "
                    "'more set Server webserver;' / Cloudflare rule).")
        if "x-powered-by" in detail:
            return ("Remove the X-Powered-By header (nginx: "
                    "'more clear_headers;' or the framework equivalent) "
                    "to stop disclosing the framework technology.")
        return "Add the missing hardening header named above."
    if category == "cookies":
        return ("Set cookie flags: Secure; HttpOnly; SameSite=Lax (or stricter) "
                "for all cookies on user-facing domains.")
    if category in ("mixed_content", "mixed content"):
        return ("Rewrite http:// asset references to https://, or emit CSP "
                "'upgrade-insecure-requests'.")
    return "Review the control named above in your server/CDN config."


def _findings(result):
    findings = result.get("findings", [])
    return findings if isinstance(findings, list) else []


def _cell(value):
    return sanitize(value).replace("|", r"\|").replace("\r", " ").replace(
        "\n", " ")


def render_section(result):
    """Render one audited URL section."""
    url = sanitize(result.get("url", ""))
    lines = [f"## {url}"]
    status = result.get("status")
    if status is None:
        lines.append("Reachability: FAILED (request did not complete)")
    else:
        final_url = sanitize(result.get("final_url", result.get("url", "")))
        lines.append(f"Reachability: final status {sanitize(status)} "
                     f"(final URL {final_url})")

    tls = result.get("tls")
    if not isinstance(tls, dict):
        tls = {}
    issuer = sanitize(tls.get("issuer_cn") or "unknown")
    expiry = sanitize(tls.get("not_after") or "unknown")
    lines.append(f"TLS: issuer CN {issuer}; expires {expiry}")

    findings = _findings(result)
    if not findings:
        lines.append("No weaknesses detected.")
        return lines

    lines.extend([
        "",
        "### Findings",
        "",
        "| Severity | Category | Detail | Remediation |",
        "| --- | --- | --- | --- |",
    ])
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = _cell(finding.get("severity", ""))
        category = _cell(finding.get("category", ""))
        detail = _cell(finding.get("detail", ""))
        fix = _cell(remediation(finding.get("category", ""),
                                finding.get("detail", "")))
        lines.append(f"| {severity} | {category} | {detail} | {fix} |")
    return lines


def render(document):
    """Render a complete audit report as Markdown."""
    results = document.get("results", [])
    findings = []
    for result in results:
        if isinstance(result, dict):
            findings.extend(_findings(result))

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    lines = [
        "# Web Hardening Audit Report",
        "",
        f"Date: {timestamp}",
        f"Scope: {len(results)} URL(s)",
        f"Verdict: {verdict(findings)}",
        "Source: hardening-audit",
        "",
        counts_summary(findings),
        "",
    ]
    for index, result in enumerate(results):
        if isinstance(result, dict):
            if index:
                lines.append("")
            lines.extend(render_section(result))
    lines.extend([
        "",
        "",
        "*This report describes wire-level observations at the time of audit "
        "only; it does not modify anything.*",
        "",
    ])
    return sanitize("\n".join(lines))


def main(argv):
    """Run the command-line report renderer."""
    if not argv or len(argv) > 3 or (len(argv) == 3 and argv[1] != "-o"):
        return 2
    input_path = argv[0]
    output_path = None
    if len(argv) == 3:
        output_path = argv[2]
    elif len(argv) == 2:
        return 2

    document = load_report(input_path)
    if document is None:
        return 2
    output = render(document)

    if output_path is None:
        sys.stdout.write(output)
        return 0
    try:
        parent = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(parent, exist_ok=True)
        with open(output_path, "w", encoding="ascii") as handle:
            handle.write(output)
    except OSError:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
