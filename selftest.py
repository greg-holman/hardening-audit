import http.server
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/weak":
            body = (
                "<!doctype html><html><body>"
                '<script src="http://cdn.example.com/x.js"></script>'
                "</body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "session=abc123; Path=/")
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/strong":
            body = (
                "<!doctype html><html><body>"
                '<script src="https://cdn.example.com/x.js"></script>'
                '<img src="https://cdn.example.com/logo.png">'
                "</body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header(
                "Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"
            )
            self.send_header(
                "Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax"
            )
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(404)

    def log_message(self, format_string, *args):
        pass


def collect_findings(value):
    found = []

    def walk(obj):
        if isinstance(obj, dict):
            keys = {str(k).lower() for k in obj}
            if keys.intersection(
                {"severity", "category", "title", "message", "finding", "rule", "id"}
            ):
                found.append(obj)
            for child in obj.values():
                walk(child)
        elif isinstance(obj, list):
            for child in obj:
                walk(child)

    walk(value)

    unique = []
    seen = set()
    for item in found:
        marker = json.dumps(item, sort_keys=True, default=str)
        if marker not in seen:
            seen.add(marker)
            unique.append(item)
    return unique


def finding_text(finding):
    return json.dumps(finding, sort_keys=True, default=str).lower()


def finding_severity(finding):
    for key in ("severity", "level", "priority"):
        value = finding.get(key)
        if value is not None:
            return str(value).lower()
    return ""


def main():
    failures = []

    def assertion(label, condition, reason="assertion failed"):
        if condition:
            print("PASS: " + label)
        else:
            print("FAIL: " + label + "  --  " + reason)
            failures.append(label)

    tool = os.environ.get("HARDENING_AUDIT_TOOL")
    if tool:
        tool = os.path.abspath(tool)
    else:
        tool = str(Path(__file__).resolve().with_name("hardening_audit.py"))

    with tempfile.TemporaryDirectory() as temp_dir:
        key_path = os.path.join(temp_dir, "localhost.key")
        cert_path = os.path.join(temp_dir, "localhost.crt")
        openssl_command = [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
        ]
        try:
            result = subprocess.run(
                openssl_command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except (FileNotFoundError, OSError):
            print("SKIP: openssl unavailable")
            return 0

        if result.returncode != 0:
            print("SKIP: openssl unavailable")
            return 0

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_socket.bind(("127.0.0.1", 0))
        raw_socket.listen(5)
        port = raw_socket.getsockname()[1]

        server = http.server.HTTPServer(
            ("127.0.0.1", port), FixtureHandler, bind_and_activate=False
        )
        try:
            server.socket.close()
        except OSError:
            pass

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        server.socket = context.wrap_socket(raw_socket, server_side=True)
        server.server_address = ("127.0.0.1", port)
        server.server_activate()

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def run_audit(path):
            url = "https://127.0.0.1:%d/%s" % (port, path)
            command = [
                sys.executable,
                tool,
                url,
                "--insecure",
                "--json",
            ]
            try:
                completed = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    check=False,
                )
            except (OSError, ValueError):
                return None, None
            try:
                parsed = json.loads(completed.stdout)
            except (TypeError, ValueError):
                parsed = None
            return completed.returncode, parsed

        try:
            weak_code, weak_json = run_audit("weak")
            strong_code, strong_json = run_audit("strong")

            weak_findings = collect_findings(weak_json)
            strong_findings = collect_findings(strong_json)

            print("Human report:")
            if weak_findings:
                for finding in weak_findings:
                    category = str(
                        finding.get("category", finding.get("type", "finding"))
                    )
                    severity = finding_severity(finding) or "unknown"
                    description = finding.get(
                        "title", finding.get("message", finding.get("rule", "finding"))
                    )
                    print("  [%s] %s: %s" % (severity, category, description))
            else:
                print("  No findings reported.")

            weak_text = [finding_text(item) for item in weak_findings]

            assertion(
                "weak audit exits with code 1",
                weak_code == 1,
                "unexpected exit code",
            )
            assertion(
                "weak report contains missing Strict-Transport-Security",
                any(
                    "strict-transport-security" in text and "missing" in text
                    for text in weak_text
                ),
                "finding not present",
            )
            assertion(
                "weak report contains missing X-Content-Type-Options",
                any(
                    "x-content-type-options" in text and "missing" in text
                    for text in weak_text
                ),
                "finding not present",
            )
            assertion(
                "weak report contains missing Referrer-Policy",
                any(
                    "referrer-policy" in text and "missing" in text
                    for text in weak_text
                ),
                "finding not present",
            )
            assertion(
                "weak report contains frame-ancestors or X-Frame-Options finding",
                any(
                    (
                        "frame-ancestors" in text
                        or "x-frame-options" in text
                    )
                    and "missing" in text
                    for text in weak_text
                ),
                "finding not present",
            )
            assertion(
                "weak report contains a cookie finding",
                any("cookie" in text for text in weak_text),
                "finding not present",
            )
            assertion(
                "weak report contains a mixed-content finding",
                any(
                    "mixed_content" in text
                    or "mixed content" in text
                    or "mixed-content" in text
                    for text in weak_text
                ),
                "finding not present",
            )

            strong_severe = [
                item
                for item in strong_findings
                if finding_severity(item) in {"high", "medium", "critical"}
            ]
            assertion(
                "strong audit exits with code 0",
                strong_code == 0,
                "unexpected exit code",
            )
            assertion(
                "strong report has no high, medium, or critical findings",
                not strong_severe,
                "severe finding reported",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    # Regression: an unresolvable URL must yield a structured critical
    # reachability finding (clean JSON, correct exit code) rather than a crash.
    unreachable_url = "https://hardening-audit-selfcheck.invalid/"
    command = [
        sys.executable,
        tool,
        unreachable_url,
        "--json",
        "--timeout",
        "5",
    ]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        completed = None
    parsed = None
    if completed is not None:
        try:
            parsed = json.loads(completed.stdout)
        except (TypeError, ValueError):
            parsed = None
    result = None
    findings = []
    if isinstance(parsed, dict) and isinstance(parsed.get("results"), list) and parsed["results"]:
        result = parsed["results"][0]
        findings = result.get("findings", [])
    assertion(
        "unreachable URL produces exactly one structured result",
        result is not None,
        "no parseable audit result",
    )
    if result is not None:
        assertion(
            "unreachable URL exits with code 2",
            completed.returncode == 2,
            "unexpected exit code",
        )
        assertion(
            "unreachable URL reports no HTTP status",
            result.get("status") is None,
            "status unexpectedly set",
        )
        assertion(
            "unreachable URL yields exactly one critical reachability finding",
            len(findings) == 1
            and findings[0].get("category") == "reachability"
            and findings[0].get("severity") == "critical",
            "finding shape mismatch",
        )
        if findings:
            detail = findings[0].get("detail")
            assertion(
                "unreachable URL finding detail is bounded and non-empty",
                isinstance(detail, str) and 0 < len(detail) <= 200,
                "detail missing or oversized",
            )

    # Regression: the report renderer must turn an audit report into a clean,
    # verdict-correct, ASCII-only Markdown document, and must fail cleanly on
    # malformed input (exit 2). Uses synthetic fixtures -- no network required.
    renderer = str(Path(__file__).resolve().with_name("report.py"))
    rdir = tempfile.mkdtemp(prefix="report_selftest_")
    fixtures = {
        "weak": {
            "results": [
                {
                    "url": "https://weak.example/",
                    "status": 200,
                    "final_url": "https://weak.example/",
                    "tls": {"issuer_cn": "TestCA", "not_after": "Jan 1 00:00:00 2030 GMT"},
                    "findings": [
                        {"category": "headers", "severity": "high",
                         "detail": "MISSING Strict-Transport-Security"},
                        {"category": "headers", "severity": "high",
                         "detail": "MISSING Referrer-Policy"},
                        {"category": "cookies", "severity": "medium",
                         "detail": "Set-Cookie lacks the Secure flag"},
                    ],
                    "counts": {"critical": 0, "high": 2, "medium": 1, "low": 0},
                }
            ]
        },
        "strong": {
            "results": [
                {
                    "url": "https://strong.example/",
                    "status": 200,
                    "final_url": "https://strong.example/",
                    "tls": {"issuer_cn": "TestCA", "not_after": "Jan 1 00:00:00 2030 GMT"},
                    "findings": [],
                    "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                }
            ]
        },
        "critical": {
            "results": [
                {
                    "url": "https://gone.example/",
                    "status": None,
                    "final_url": None,
                    "tls": {"issuer_cn": "", "not_after": None},
                    "findings": [
                        {"category": "reachability", "severity": "critical",
                         "detail": "ValueError: host unreachable"}
                    ],
                    "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
                }
            ]
        },
    }

    def render_fixture(name):
        path = os.path.join(rdir, name + ".json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(fixtures[name], handle)
        command = [sys.executable, renderer, path]
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
                timeout=30,
            )
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return None, None
        return completed.returncode, completed.stdout

    weak_rc, weak_md = render_fixture("weak")
    strong_rc, strong_md = render_fixture("strong")
    crit_rc, crit_md = render_fixture("critical")

    assertion("renderer exits 0 on a weak report", weak_rc == 0, "unexpected exit code")
    assertion("renderer exits 0 on a strong report", strong_rc == 0, "unexpected exit code")
    assertion("renderer exits 0 on a critical report", crit_rc == 0, "unexpected exit code")
    if weak_md is not None:
        assertion(
            "weak report verdict is NEEDS ATTENTION",
            "Verdict: NEEDS ATTENTION" in weak_md,
            "verdict line missing or wrong",
        )
        assertion(
            "weak report routes every finding through a remediation cell",
            all(line.count("|") >= 4 for line in weak_md.splitlines()
                if line.startswith("|") and "---" not in line and "Severity" not in line),
            "a remediation cell appears empty",
        )
        assertion(
            "weak report is pure printable ASCII",
            all(c in "\n\t" or 0x20 <= ord(c) <= 0x7E for c in weak_md),
            "non-ASCII character surfaced",
        )
    if strong_md is not None:
        assertion("strong report verdict is PASS", "Verdict: PASS" in strong_md, "verdict wrong")
        assertion("strong report reports no findings", "Findings: none" in strong_md, "counts line wrong")
    if crit_md is not None:
        assertion("critical report verdict is FAIL", "Verdict: FAIL" in crit_md, "verdict wrong")
        assertion("critical report shows reachability failure", "Reachability: FAILED" in crit_md, "reachability line missing")

    malformed_path = os.path.join(rdir, "malformed.json")
    with open(malformed_path, "w", encoding="utf-8") as handle:
        handle.write("this is not json")
    try:
        malformed = subprocess.run(
            [sys.executable, renderer, malformed_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        malformed = None
    assertion(
        "malformed input exits 2",
        malformed is not None and malformed.returncode == 2,
        "expected exit code 2",
    )

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
