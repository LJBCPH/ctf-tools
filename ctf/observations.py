"""Transform raw scan results into a flat list of UI-ready observation rows.

Each row is one fact about the target — no severity, no CVSS, just structured
information shaped for a table in a frontend. Severity / CVE enrichment will
be a separate pass once a CVE database is wired in.

Usage:
    from ctf.scan import run_scan
    from ctf.observations import to_observations

    raw = run_scan("https://target.example.com")
    rows = to_observations(raw)
    # rows is JSON-serializable: List[Dict] ready for FastAPI response
"""
from __future__ import annotations

from typing import Any, Iterable
from urllib.parse import urlparse

# Headers we always check for presence; missing → one observation each.
_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Headers that disclose product/version when present.
_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def _port_from_url(url: str | None) -> int | None:
    """Derive the TCP port a URL implies. https://x → 443, http://x → 80,
    and explicit ':NNNN' wins. Used so URL-level findings (missing headers,
    cookies, technologies, content) can be attributed to the port they
    were actually observed on."""
    if not url:
        return None
    p = urlparse(url)
    if p.port:
        return p.port
    if p.scheme == "https":
        return 443
    if p.scheme == "http":
        return 80
    return None


def to_observations(scan: dict) -> list[dict]:
    """Flatten a scan result into observation rows.

    Each row carries the port the finding lives on:
      - port-scan rows (OPEN_PORT, BANNER, TLS_*, HTTP_ON_PORT) — port from scan
      - URL-level rows (HTTP_*, MISSING_*, TECHNOLOGY, content, discovery) —
        port derived from the analyzed URL (final_url after redirects, falling
        back to resolved_url if the request failed)
      - host-level rows (OS_FINGERPRINT) — port=null (genuinely whole-host)
    """
    host = scan.get("host")
    target = scan.get("target")

    # URL-level findings inherit the port the URL implies. Prefer the post-redirect
    # final URL since that's where headers/cookies/body actually came from.
    http = scan.get("http") or {}
    url_for_port = http.get("final_url") or scan.get("resolved_url")
    url_port = _port_from_url(url_for_port)

    rows: list[dict] = []
    counter = _Counter()

    rows.extend(_obs_os(scan, host, counter))
    rows.extend(_obs_ports(scan, host, counter))
    rows.extend(_obs_http(scan, host, target, url_port, counter))
    rows.extend(_obs_technologies(scan, host, url_port, counter))
    rows.extend(_obs_content(scan, host, url_port, counter))
    rows.extend(_obs_discovery(scan, host, url_port, counter))

    return rows


# ---------------------------------------------------------------------------
# Per-section extractors
# ---------------------------------------------------------------------------

def _obs_os(scan: dict, host: str, c: "_Counter") -> Iterable[dict]:
    os_info = scan.get("os") or {}
    if not os_info:
        return
    yield _row(
        c, "OS_FINGERPRINT", "Operating System Fingerprint",
        category="Service Discovery", host=host, port=None,
        evidence=os_info, source="nmap",
        title_extra=os_info.get("name"),
    )


def _obs_ports(scan: dict, host: str, c: "_Counter") -> Iterable[dict]:
    for p in scan.get("ports", []) or []:
        port = p.get("port")
        proto = p.get("protocol", "tcp")
        service = p.get("service") or "unknown"
        product = p.get("product") or ""
        version = p.get("version") or ""

        # Top-level open port row.
        title_bits = [f"Open port {port}/{proto}", service]
        if product:
            title_bits.append(product)
        if version:
            title_bits.append(version)
        yield _row(
            c, "OPEN_PORT", " — ".join(title_bits),
            category="Service Discovery", host=host, port=port,
            evidence={
                "service": service, "product": product, "version": version,
                "extrainfo": p.get("extrainfo", ""),
                "ostype": p.get("ostype", ""),
                "cpes": p.get("cpes", []),
            },
            source="nmap" if p.get("cpes") else "socket",
        )

        probes = p.get("probes") or {}

        # Banner observation.
        banner = probes.get("raw_banner")
        if banner and banner.get("ascii"):
            first_line = banner["ascii"].splitlines()[0][:200] if banner["ascii"] else ""
            yield _row(
                c, "BANNER", f"Service banner on {port}/{proto}: {first_line}",
                category="Service Discovery", host=host, port=port,
                evidence={"bytes": banner.get("bytes"), "ascii": banner.get("ascii"), "hex": banner.get("hex")},
                source="banner_probe",
            )

        # TLS observations.
        tls = probes.get("tls")
        if tls and tls.get("present"):
            yield _row(
                c, "TLS_PROTOCOL_VERSION",
                f"TLS negotiated on {port}: {tls.get('version', 'unknown')}",
                category="Cryptography", host=host, port=port,
                evidence={"version": tls.get("version"), "cipher": tls.get("cipher")},
                source="tls_probe",
            )
            if tls.get("subject") or tls.get("issuer"):
                yield _row(
                    c, "TLS_CERTIFICATE",
                    f"TLS certificate on {port}",
                    category="Cryptography", host=host, port=port,
                    evidence={
                        "subject": tls.get("subject", {}),
                        "issuer": tls.get("issuer", {}),
                        "not_before": tls.get("not_before"),
                        "not_after": tls.get("not_after"),
                        "san": tls.get("san", []),
                    },
                    source="tls_probe",
                )

        # HTTP-on-port observation (catches Elasticsearch/Kibana/etc on any port).
        http = probes.get("http")
        if http:
            title = http.get("title") or http.get("scheme", "http").upper()
            yield _row(
                c, "HTTP_ON_PORT",
                f"HTTP service on {port} — {title}",
                category="Service Discovery", host=host, port=port,
                evidence={
                    "scheme": http.get("scheme"),
                    "status_code": http.get("status_code"),
                    "title": http.get("title"),
                    "headers": http.get("headers", {}),
                    "body_excerpt": http.get("body_excerpt", "")[:400],
                },
                source="http_probe",
            )


def _obs_http(scan: dict, host: str, target: str, port: int | None, c: "_Counter") -> Iterable[dict]:
    http = scan.get("http") or {}
    if not http or http.get("error"):
        if http.get("error"):
            yield _row(
                c, "HTTP_ERROR", f"HTTP request failed: {http['error']}",
                category="Service Discovery", host=host, port=port,
                evidence={"error": http["error"], "target": target},
                source="http",
            )
        return

    headers = http.get("headers", {})

    # Status + redirects.
    yield _row(
        c, "HTTP_RESPONSE",
        f"HTTP {http.get('status_code')} from {http.get('final_url', target)}",
        category="Service Discovery", host=host, port=port,
        evidence={
            "status_code": http.get("status_code"),
            "final_url": http.get("final_url"),
            "redirect_chain": http.get("redirect_chain", []),
        },
        source="http",
    )

    # Disclosure headers — one row per header found.
    for name in _DISCLOSURE_HEADERS:
        if name in headers:
            yield _row(
                c, "HTTP_HEADER_DISCLOSURE",
                f"{name} header reveals: {headers[name]}",
                category="Information Disclosure", host=host, port=port,
                evidence={"header": name, "value": headers[name]},
                source="http",
            )

    # Missing security headers — one row per missing header.
    for name in _SECURITY_HEADERS:
        if name not in headers:
            yield _row(
                c, "MISSING_SECURITY_HEADER",
                f"Missing security header: {name}",
                category="Configuration", host=host, port=port,
                evidence={"header": name},
                source="http",
            )

    # Cookies — one row per cookie, with flags.
    for cookie in http.get("cookies", []) or []:
        missing_flags = []
        if not cookie.get("secure"):
            missing_flags.append("Secure")
        if not cookie.get("httponly"):
            missing_flags.append("HttpOnly")
        if not cookie.get("samesite"):
            missing_flags.append("SameSite")
        yield _row(
            c, "COOKIE_FLAGS",
            f"Cookie '{cookie.get('name')}' flags: " + (
                "all set" if not missing_flags else f"missing {', '.join(missing_flags)}"
            ),
            category="Configuration", host=host, port=port,
            evidence=cookie,
            source="http",
        )


def _obs_technologies(scan: dict, host: str, port: int | None, c: "_Counter") -> Iterable[dict]:
    for tech in scan.get("technologies", []) or []:
        if tech.get("name") == "Missing Security Headers":
            # Already emitted as MISSING_SECURITY_HEADER rows.
            continue
        yield _row(
            c, "TECHNOLOGY",
            f"{tech.get('name')} ({tech.get('category')})",
            category="Technology", host=host, port=port,
            evidence=tech,
            source="fingerprint",
        )


def _obs_content(scan: dict, host: str, port: int | None, c: "_Counter") -> Iterable[dict]:
    content = scan.get("content") or {}

    for form in content.get("forms", []) or []:
        yield _row(
            c, "HTML_FORM",
            f"{form.get('method', 'GET')} form → {form.get('action')}",
            category="Content", host=host, port=port,
            evidence=form,
            source="content",
        )

    for email in content.get("emails", []) or []:
        yield _row(
            c, "EMAIL_DISCLOSURE", f"Email exposed: {email}",
            category="Information Disclosure", host=host, port=port,
            evidence={"email": email},
            source="content",
        )

    for js in content.get("js_files", []) or []:
        # JS files may be hosted on a different origin (CDN). If so, the row
        # is still attributable to the *page* port that referenced them.
        yield _row(
            c, "JS_FILE", f"JavaScript bundle: {js}",
            category="Content", host=host, port=port,
            evidence={"url": js},
            source="content",
        )

    for comment in content.get("html_comments", []) or []:
        yield _row(
            c, "HTML_COMMENT", f"HTML comment: {comment[:120]}",
            category="Information Disclosure", host=host, port=port,
            evidence={"comment": comment},
            source="content",
        )


def _obs_discovery(scan: dict, host: str, port: int | None, c: "_Counter") -> Iterable[dict]:
    discovery = scan.get("discovery") or {}
    for key, info in discovery.items():
        if not info or info.get("status_code") != 200:
            continue
        yield _row(
            c, f"WELL_KNOWN_{key.upper()}",
            f"{key.replace('_', '.')} accessible",
            category="Information Disclosure", host=host, port=port,
            evidence={"url": info.get("url"), "content": info.get("content")},
            source="well_known",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _Counter:
    """Stamps each row with a sequential numeric id for the UI table."""
    def __init__(self):
        self._n = 0

    def next(self) -> int:
        self._n += 1
        return self._n


def _row(
    c: _Counter,
    rule_id: str,
    title: str,
    *,
    category: str,
    host: str | None,
    port: int | None,
    evidence: dict[str, Any],
    source: str,
    title_extra: str | None = None,
) -> dict:
    if title_extra:
        title = f"{title}: {title_extra}"
    return {
        "row_id": c.next(),
        "id": rule_id,
        "title": title,
        "category": category,
        "host": host,
        "port": port,
        "evidence": evidence,
        "source": source,
    }
