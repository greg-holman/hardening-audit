"""HTTPS web-hardening audit tool. It checks HSTS strictness, CSP weakness, and Server/X-Powered-By disclosure checks. Install: copy this file and run `python hardening_audit.py https://example.com`. Example: `python hardening_audit.py --json https://example.com`."""

import argparse
import json
import re
import ssl
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPHandler, HTTPSHandler


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def short_exception(exc, url):
    """One-line, length-bounded description of an exception for audit findings.

    Scrubs URL userinfo (user:pass@) from the text. Avoids urlsplit()._replace()
    with userinfo kwargs -- that signature changed across Python versions and
    crashes on newer runtimes.
    """
    lines = str(exc).splitlines()
    text = lines[0].strip() if lines else ""
    if url:
        scrubbed = re.sub(
            r"(^[a-z][a-z0-9+.-]*://)[^@/]+@",
            r"\1",
            url,
            count=1,
            flags=re.IGNORECASE | re.ASCII,
        )
        text = text.replace(url, scrubbed)

        def clean(match):
            return re.sub(
                r"(^[a-z][a-z0-9+.-]*://)[^@/]+@",
                r"\1",
                match.group(0),
                count=1,
                flags=re.IGNORECASE | re.ASCII,
            )

        text = re.sub(r"[a-z][a-z0-9+.-]*://[^\s]+", clean, text, flags=re.IGNORECASE | re.ASCII)
    name = type(exc).__name__
    limit = max(0, 180 - len(name) - 2)
    if len(text) > limit:
        text = text[:max(0, limit - 3)] + "..."
    return f"{name}: {text}" if text else name


def cn_from_name(name):
    if not name:
        return ""
    for group in name:
        for key, value in group:
            if key.lower() == "commonname":
                return value
    return ""


def certificate_info(response):
    empty = {"issuer_cn": "", "subject_cn": "", "not_after": None}
    sock = None
    try:
        obj = response.fp
        for attr in ("raw", "_sock", "sock"):
            if obj is not None and hasattr(obj, attr):
                obj = getattr(obj, attr)
        sock = obj
        if sock is None or not hasattr(sock, "getpeercert"):
            return empty
        cert = sock.getpeercert()
        if not cert:
            der = sock.getpeercert(binary_form=True)
            if not der:
                return empty
            pem = ssl.DER_cert_to_PEM_cert(der)
            with tempfile.NamedTemporaryFile("w", encoding="ascii") as handle:
                handle.write(pem)
                handle.flush()
                cert = ssl._ssl._test_decode_cert(handle.name)
        return {
            "issuer_cn": cn_from_name(cert.get("issuer")),
            "subject_cn": cn_from_name(cert.get("subject")),
            "not_after": cert.get("notAfter"),
        }
    except Exception:
        return empty


def parse_cert_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            return None


def add_finding(findings, category, severity, detail):
    findings.append({"category": category, "severity": severity, "detail": detail})


def cookie_findings(cookies, findings):
    for cookie in cookies:
        flags = {}
        for item in cookie.split(";")[1:]:
            part = item.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                flags[key.strip().lower()] = value.strip().lower()
            else:
                flags[part.lower()] = None
        if "secure" not in flags:
            add_finding(findings, "cookies", "medium",
                        "Set-Cookie lacks the Secure flag")
        if "httponly" not in flags:
            add_finding(findings, "cookies", "low",
                        "Set-Cookie lacks the HttpOnly flag")
        if "samesite" not in flags or flags.get("samesite") == "none":
            add_finding(findings, "cookies", "low",
                        "Set-Cookie has SameSite absent or set to None")


def mixed_content_findings(body, limit, findings):
    found = []
    pattern = re.compile(r"http://[^\s\"'<>]+", re.IGNORECASE)
    for match in pattern.findall(body):
        value = match.rstrip(".,;:)]}")
        if value not in found:
            found.append(value)
        if len(found) >= limit:
            break
    for value in found:
        add_finding(findings, "mixed_content", "medium", value)


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_RANK[item["severity"]],
            item["category"],
            item["detail"],
        ),
    )


def audit_url(url, args):
    result = {
        "url": url,
        "final_url": None,
        "status": None,
        "tls": {"issuer_cn": "", "subject_cn": "", "not_after": None},
        "findings": [],
    }
    findings = result["findings"]

    if args.insecure:
        add_finding(findings, "tls", "low", "TLS certificate verification was skipped")

    if urlsplit(url).scheme.lower() != "https":
        add_finding(findings, "reachability", "critical",
                    "ValueError: URL must use HTTPS")
        result["findings"] = sort_findings(findings)
        return result

    context = ssl._create_unverified_context() if args.insecure else ssl.create_default_context()
    opener = build_opener(HTTPSHandler(context=context), HTTPHandler())
    request = Request(
        url,
        headers={
            "User-Agent": "hardening-audit/1.0 (Python urllib)",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        },
        method="GET",
    )

    response = None
    try:
        response = opener.open(request, timeout=args.timeout)
    except HTTPError as exc:
        response = exc
    except Exception as exc:
        add_finding(findings, "reachability", "critical",
                    short_exception(exc, url))
        result["findings"] = sort_findings(findings)
        return result

    try:
        result["final_url"] = response.geturl()
        result["status"] = getattr(response, "status", None) or response.getcode()
        result["tls"] = certificate_info(response)

        headers = {}
        for key in response.headers.keys():
            lower = key.lower()
            headers.setdefault(lower, response.headers.get_all(key) or [])

        set_cookies = response.headers.get_all("Set-Cookie") or []
        content_type = response.headers.get("Content-Type", "")
        body = b""
        if content_type.lower().split(";", 1)[0].strip() == "text/html":
            body = response.read(400 * 1024)

        if not 200 <= result["status"] <= 299:
            add_finding(
                findings,
                "reachability",
                "high",
                f"Final HTTP status was {result['status']}",
            )

        if not args.insecure:
            cert_date = parse_cert_date(result["tls"].get("not_after"))
            if cert_date is not None:
                now = datetime.now(timezone.utc)
                if cert_date < now:
                    add_finding(findings, "tls", "high",
                                f"TLS certificate expired on {result['tls']['not_after']}")
                elif cert_date <= now.replace() + __import__("datetime").timedelta(days=14):
                    add_finding(findings, "tls", "medium",
                                f"TLS certificate expires on {result['tls']['not_after']}")
            if not result["tls"].get("issuer_cn"):
                add_finding(findings, "tls", "low",
                            "TLS certificate issuer CN is empty or unknown")

        hsts = response.headers.get("Strict-Transport-Security")
        xcto = response.headers.get("X-Content-Type-Options")
        referrer = response.headers.get("Referrer-Policy")
        csp = response.headers.get("Content-Security-Policy")
        xfo = response.headers.get("X-Frame-Options")

        if not hsts:
            add_finding(findings, "headers", "high",
                        "MISSING Strict-Transport-Security")
        elif not re.search(r"(?:^|;)\s*max-age\s*=", hsts, re.IGNORECASE):
            add_finding(findings, "headers", "medium",
                        "Strict-Transport-Security is present without max-age=")
        if not xcto or xcto.strip().lower() != "nosniff":
            add_finding(findings, "headers", "high",
                        "MISSING or invalid X-Content-Type-Options (expected nosniff)")
        if not referrer:
            add_finding(findings, "headers", "high", "MISSING Referrer-Policy")
        if not xfo and not (csp and re.search(r"(?:^|;)\s*frame-ancestors\b", csp, re.IGNORECASE)):
            if csp is None:
                add_finding(findings, "headers", "high",
                            "MISSING clickjacking protection (no X-Frame-Options or CSP frame-ancestors)")
            else:
                add_finding(findings, "headers", "high",
                            "CSP lacks frame-ancestors and no X-Frame-Options present")

        if "strict-transport-security" in headers:
            hsts_value = " ".join(headers["strict-transport-security"])
            if (
                not re.search(r"(?:^|;)\s*includeSubDomains\b", hsts_value, re.IGNORECASE)
                or not re.search(r"(?:^|;)\s*preload\b", hsts_value, re.IGNORECASE)
            ):
                add_finding(
                    findings,
                    "headers",
                    "low",
                    "Strict-Transport-Security lacks includeSubDomains and/or preload",
                )

        if "content-security-policy" in headers:
            csp_value = re.sub(r"\s+", " ", " ".join(headers["content-security-policy"])).lower()
            if "unsafe-inline" in csp_value or "unsafe-eval" in csp_value:
                add_finding(
                    findings,
                    "headers",
                    "low",
                    "Content-Security-Policy permits 'unsafe-inline' and/or 'unsafe-eval'",
                )

        if any(value.strip() for value in headers.get("server", [])):
            add_finding(
                findings,
                "headers",
                "low",
                "Server response header discloses web server technology",
            )

        if any(value.strip() for value in headers.get("x-powered-by", [])):
            add_finding(
                findings,
                "headers",
                "low",
                "X-Powered-By response header discloses framework technology",
            )

        cookie_findings(set_cookies, findings)
        if body:
            mixed_content_findings(body.decode("utf-8", "replace"), args.max_mixed, findings)
    finally:
        response.close()

    result["findings"] = sort_findings(findings)
    return result


def counts(findings):
    counter = Counter(item["severity"] for item in findings)
    return {key: counter.get(key, 0) for key in ("critical", "high", "medium", "low")}


def human_report(result):
    print(f"URL: {result['url']}")
    if result["status"] is None:
        print("Reachability: request failed")
    else:
        print(f"Reachability: final status {result['status']} ({result['final_url']})")
    findings = result["findings"]
    for severity in ("critical", "high", "medium", "low"):
        matches = [f for f in findings if f["severity"] == severity]
        if matches:
            print(f"{severity.capitalize()}:")
            for finding in matches:
                print(f"  - {finding['category']}: {finding['detail']}")
    if not findings:
        print("PASS - no weaknesses detected.")
    else:
        c = counts(findings)
        parts = ", ".join(f"{c[key]} {key}" for key in ("critical", "high", "medium", "low") if c[key])
        print(f"{len(findings)} findings ({parts})")
    print()


def main():
    parser = argparse.ArgumentParser(description="Audit HTTPS URLs for web-hardening weaknesses.")
    parser.add_argument("urls", nargs="+")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--max-mixed", type=int, default=5)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    args.max_mixed = max(0, args.max_mixed)

    results = []
    for url in args.urls:
        if args.verbose:
            print(f"Auditing {url}", file=sys.stderr)
        results.append(audit_url(url, args))

    if args.as_json:
        output = []
        for result in results:
            item = dict(result)
            item["counts"] = counts(item["findings"])
            output.append(item)
        print(json.dumps({"results": output}, sort_keys=True))
    else:
        for result in results:
            human_report(result)

    all_findings = [finding for result in results for finding in result["findings"]]
    if any(f["severity"] == "critical" for f in all_findings):
        return 2
    if any(f["severity"] == "high" for f in all_findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
