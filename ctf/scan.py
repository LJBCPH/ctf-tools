import json
import os
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import click
import requests
import urllib3
from rich.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

# ---------------------------------------------------------------------------
# Technology fingerprints: (pattern, name, category)
# ---------------------------------------------------------------------------
_HEADER_FINGERPRINTS = [
    # Server / framework
    (r"nginx",              "nginx",           "Web Server"),
    (r"apache",             "Apache",          "Web Server"),
    (r"iis",                "IIS",             "Web Server"),
    (r"lighttpd",           "lighttpd",        "Web Server"),
    (r"caddy",              "Caddy",           "Web Server"),
    (r"gunicorn",           "Gunicorn",        "Python WSGI"),
    (r"uvicorn",            "Uvicorn",         "Python ASGI"),
    (r"php/[\d.]+",         "PHP",             "Language"),
    (r"express",            "Express",         "Node.js Framework"),
    (r"django",             "Django",          "Python Framework"),
    (r"flask",              "Flask",           "Python Framework"),
    (r"rails",              "Ruby on Rails",   "Ruby Framework"),
    (r"laravel",            "Laravel",         "PHP Framework"),
    (r"wordpress",          "WordPress",       "CMS"),
    (r"drupal",             "Drupal",          "CMS"),
    (r"joomla",             "Joomla",          "CMS"),
    (r"shopify",            "Shopify",         "E-Commerce"),
    (r"cloudflare",         "Cloudflare",      "CDN / WAF"),
    (r"akamai",             "Akamai",          "CDN"),
    (r"varnish",            "Varnish",         "Cache"),
    (r"fastly",             "Fastly",          "CDN"),
]

_HTML_FINGERPRINTS = [
    (r"wp-content|wp-includes",          "WordPress",         "CMS"),
    (r"Joomla",                          "Joomla",            "CMS"),
    (r"Drupal\.settings",                "Drupal",            "CMS"),
    (r"ng-version|angular\.js",          "Angular",           "JS Framework"),
    (r"__NEXT_DATA__|_next/static",      "Next.js",           "JS Framework"),
    (r"__nuxt__|_nuxt/",                 "Nuxt.js",           "JS Framework"),
    (r"data-reactroot|__REACT_DEVTOOLS", "React",             "JS Library"),
    (r"vue\.js|Vue\.config",             "Vue.js",            "JS Framework"),
    (r"svelte",                          "Svelte",            "JS Framework"),
    (r"jquery[.-][\d.]+",                "jQuery",            "JS Library"),
    (r"bootstrap\.min\.css|bootstrap\.bundle", "Bootstrap",   "CSS Framework"),
    (r"tailwindcss",                     "Tailwind CSS",      "CSS Framework"),
    (r"gtag\(|google-analytics\.com",    "Google Analytics",  "Analytics"),
    (r"gtm\.js|googletagmanager",        "Google Tag Manager","Analytics"),
    (r"intercom",                        "Intercom",          "Support"),
    (r"recaptcha",                       "reCAPTCHA",         "Security"),
    (r"stripe\.js|js\.stripe\.com",      "Stripe",            "Payments"),
    (r"graphql",                         "GraphQL",           "API"),
]


@click.group()
def scan():
    """Full-spectrum target scan — outputs structured JSON."""
    pass


DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,8888,9200,27017"


def _normalize_target(raw: str) -> dict:
    """Accept any of: bare IP, IP:port, hostname, hostname:port, or full URL.

    Returns a dict with the bits the scan needs:
      host       — what the port scan / probes target (always set)
      url        — full URL for HTTP analysis, or None if no scheme given
      origin     — scheme://netloc for well-known fetches, or None
      port_hint  — explicit port the user named (added to scan list), or None
    """
    raw = raw.strip()

    # Has a scheme → parse as URL.
    if "://" in raw:
        parsed = urlparse(raw)
        return {
            "input": raw,
            "host": parsed.hostname,
            "url": raw,
            "origin": f"{parsed.scheme}://{parsed.netloc}",
            "port_hint": parsed.port,
        }

    # Bare host[:port]. Naive split — does not support IPv6 brackets.
    host, _, port_s = raw.partition(":")
    port_hint = None
    if port_s:
        try:
            port_hint = int(port_s)
        except ValueError:
            host = raw  # weird input, treat the whole thing as the host

    return {
        "input": raw,
        "host": host or raw,
        "url": None,
        "origin": None,
        "port_hint": port_hint,
    }


def run_scan(
    target: str,
    ports: str = DEFAULT_PORTS,
    include_ports: bool = True,
    include_discovery: bool = True,
    include_icmp: bool = False,
    quiet: bool = False,
) -> dict:
    """Run a scan and return the raw result dict.

    Accepts any of:
      - bare IP:           "1.2.3.4"
      - IP with port:      "1.2.3.4:9200"
      - bare hostname:     "example.com"
      - full URL:          "https://example.com/login"

    Importable from FastAPI / any Python code:

        from ctf.scan import run_scan
        from ctf.observations import to_observations

        raw = run_scan("1.2.3.4")
        rows = to_observations(raw)
        return {"scan": raw, "observations": rows}
    """
    t = _normalize_target(target)
    host, url, origin, port_hint = t["host"], t["url"], t["origin"], t["port_hint"]

    result = {
        "target": target,
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ports": [],
        "os": {},
        "http": {},
        "technologies": [],
        "content": {},
        "discovery": {},
        "icmp": {},
    }

    port_list: list[int] = []
    if include_ports:
        port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        if port_hint and port_hint not in port_list:
            port_list.append(port_hint)

    # If the caller gave us a bare IP/host, auto-resolve a URL by probing
    # candidate scheme/port combos. Runs in parallel with the port scan so
    # we don't pay the latency twice.
    with ThreadPoolExecutor(max_workers=4) as pool:
        f_ports = pool.submit(_port_scan, host, port_list) if include_ports else None
        f_resolve = pool.submit(_resolve_url, host, port_hint) if not url else None
        f_icmp = pool.submit(_icmp_timestamp, host) if include_icmp else None

        if f_ports:
            result["ports"], result["os"] = f_ports.result()
        if f_resolve:
            url, origin = f_resolve.result()
        if f_icmp:
            result["icmp"] = f_icmp.result()

    if not quiet:
        mode = "url" if t["url"] else ("auto-url" if url else "host-only")
        console.print(f"[cyan][*][/cyan] Scanning [bold]{host}[/bold] ({mode}, "
                      f"resolved={url or 'none'})...")

    result["resolved_url"] = url

    # Phase 2: URL-driven analyses, parallelized. Run unconditionally whenever
    # we ended up with a URL — synthesized or caller-provided, no difference.
    if url:
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_http = pool.submit(_http_analysis, url)
            f_well_known = pool.submit(_well_known, origin) if include_discovery else None
            result["http"] = f_http.result()
            if f_well_known:
                result["discovery"] = f_well_known.result()

        if result["http"] and not result["http"].get("error"):
            result["technologies"] = _fingerprint(result["http"])
            result["content"] = _content_analysis(url, origin, result["http"].get("body", ""))
            result["http"].pop("body", None)

    return result


@scan.command(name="run")
@click.option("-t", "--target", required=True,
              help="Target — IP, IP:port, hostname, hostname:port, or full URL. "
                   "When no scheme is given, the scanner auto-resolves a URL "
                   "by probing https/http on the host (and port hint if any).")
@click.option("-p", "--ports", default=DEFAULT_PORTS,
              show_default=True, help="Comma-separated ports to probe")
@click.option("--no-ports", is_flag=True, help="Skip port scanning entirely")
@click.option("--no-discovery", is_flag=True, help="Skip robots/sitemap/security.txt fetch")
@click.option("--icmp", "include_icmp", is_flag=True,
              help="Also send an ICMP timestamp probe (CVE-1999-0524). "
                   "Needs a raw socket: root / CAP_NET_RAW, or Administrator.")
@click.option("--observations", "as_observations", is_flag=True,
              help="Emit flat observations list (UI-ready rows) instead of raw scan tree")
@click.option("-o", "--output", default=None, help="Write JSON to this file instead of stdout")
def run(target, ports, no_ports, no_discovery, include_icmp, as_observations, output):
    """Run a full passive + active scan and emit JSON results."""
    from ctf.observations import to_observations

    raw = run_scan(
        target=target,
        ports=ports,
        include_ports=not no_ports,
        include_discovery=not no_discovery,
        include_icmp=include_icmp,
    )

    payload = to_observations(raw) if as_observations else raw
    out = json.dumps(payload, indent=2, default=str)

    if output:
        with open(output, "w") as f:
            f.write(out)
        console.print(f"\n[green][+][/green] Results written to [bold]{output}[/bold]")
    else:
        print(out)


@scan.command(name="icmp")
@click.option("-t", "--target", required=True,
              help="Target — IP or hostname (any port/scheme in the value is ignored)")
@click.option("--timeout", default=2.0, show_default=True, type=float,
              help="Seconds to wait for the timestamp reply")
@click.option("-o", "--output", default=None, help="Write JSON to this file instead of stdout")
def icmp(target, timeout, output):
    """Probe for ICMP Timestamp responses (CVE-1999-0524).

    A host that answers an ICMP Timestamp Request (ICMP type 13) with a
    Timestamp Reply (type 14) discloses its system clock — the low-severity
    information leak that Nessus (plugin 10114), Qualys (82003) and OpenVAS
    report as CVE-1999-0524. Sending/receiving raw ICMP needs elevated
    privileges (root / CAP_NET_RAW on Linux, Administrator on Windows).
    """
    t = _normalize_target(target)
    res = _icmp_timestamp(t["host"], timeout=timeout)

    out = json.dumps(res, indent=2, default=str)
    if output:
        with open(output, "w") as f:
            f.write(out)
        console.print(f"\n[green][+][/green] Results written to [bold]{output}[/bold]")
    else:
        print(out)

    if res.get("responded"):
        console.print(
            f"[yellow][!][/yellow] [bold]{t['host']}[/bold] answers ICMP timestamp "
            f"requests — CVE-1999-0524 (system clock disclosed)."
        )
    elif res.get("error"):
        console.print(f"[red][x][/red] {res['error']}")
    else:
        console.print(
            f"[green][+][/green] [bold]{t['host']}[/bold] did not answer "
            f"(type 13 filtered or ignored)."
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Generic banner/version regexes — applied to ANY captured probe response.
# Order matters: most-specific first.
# ---------------------------------------------------------------------------
_BANNER_FINGERPRINTS = [
    # protocol             pattern                                              service          extract version group
    ("ssh",   re.compile(rb"^SSH-([\d.]+)-(\S+)", re.I),                         "ssh",            2),
    ("ftp",   re.compile(rb"^220[- ].*?(ProFTPD|vsftpd|Pure-FTPd|FileZilla|Microsoft FTP)[ /]?([\d.]*)", re.I), "ftp", 0),
    ("smtp",  re.compile(rb"^220[- ].*?(Postfix|Sendmail|Exim|Microsoft ESMTP)[ /]?([\d.]*)", re.I), "smtp", 0),
    ("pop3",  re.compile(rb"^\+OK.*?(Dovecot|Courier)[ /]?([\d.]*)", re.I),      "pop3",           0),
    ("imap",  re.compile(rb"^\* OK.*?(Dovecot|Courier|Cyrus)[ /]?([\d.]*)", re.I), "imap",         0),
    ("redis", re.compile(rb"-ERR|^\+PONG|redis_version:([\d.]+)", re.I),         "redis",          1),
    ("mysql", re.compile(rb"\x00\x00\x00\x0a([\d.]+)\x00", re.I),                "mysql",          1),
    ("mongo", re.compile(rb"MongoDB|isMaster|topologyVersion", re.I),            "mongodb",        0),
    ("rdp",   re.compile(rb"^\x03\x00", re.I),                                   "rdp",            0),
    ("smb",   re.compile(rb"SMB|\xffSMB|\xfeSMB", re.I),                         "smb",            0),
    ("vnc",   re.compile(rb"^RFB ([\d.]+)", re.I),                               "vnc",            1),
]

# HTTP body fingerprints — applied to whatever HTTP GET / returns,
# regardless of port. This is what catches Elasticsearch on 9200,
# Kibana on 5601, Jenkins, Prometheus, etc.
_HTTP_BODY_FINGERPRINTS = [
    (re.compile(r'"You Know, for Search"|"cluster_name"\s*:|"tagline"\s*:\s*"You Know'), "elasticsearch"),
    (re.compile(r'"name"\s*:\s*"Kibana"|kbn-name'), "kibana"),
    (re.compile(r'X-Jenkins|Jenkins-Version'), "jenkins"),
    (re.compile(r'<title>Grafana'), "grafana"),
    (re.compile(r'# HELP \w+|# TYPE \w+'), "prometheus"),
    (re.compile(r'"rabbitmq_version"|RabbitMQ Management'), "rabbitmq"),
    (re.compile(r'<title>phpMyAdmin'), "phpmyadmin"),
    (re.compile(r'"docker_version"|"ApiVersion"\s*:'), "docker-api"),
    (re.compile(r'consul'), "consul"),
    (re.compile(r'etcdserver'), "etcd"),
    (re.compile(r'<title>Portainer|portainer\.io'), "portainer"),
    (re.compile(r'<title>Traefik|traefik'), "traefik"),
    (re.compile(r'minio'), "minio"),
]


def _port_scan(host: str, ports: list[int]) -> tuple[list[dict], dict]:
    """Two-stage port scan:
      1. Fast TCP-connect scan (always runs, always reliable, ~1.5s).
      2. If nmap is available AND any ports came back open, enrich those
         specific ports with -sV/-O for service version + OS fingerprint.

    This avoids the failure mode where nmap on a heavily-filtered IP
    (Cloudflare, AWS frontends) times out doing OS detection and returns
    nothing, leaving us with no port info at all."""
    os_info: dict = {}
    results = _socket_scan(host, ports)
    open_entries = [e for e in results if e.get("state") == "open"]

    if open_entries and shutil.which("nmap"):
        open_port_list = [e["port"] for e in open_entries]
        nmap_results, os_info = _nmap_scan(host, open_port_list)
        if nmap_results:
            # Merge: nmap row replaces socket row when they agree on a port.
            by_port = {e["port"]: e for e in results}
            for nr in nmap_results:
                by_port[nr["port"]] = nr
            results = sorted(by_port.values(), key=lambda r: r["port"])
            open_entries = [e for e in results if e.get("state") == "open"]

    # Generic probe pass — concurrent across all open ports so total enrichment
    # time is bounded by the slowest single port, not summed across them.
    if open_entries:
        with ThreadPoolExecutor(max_workers=min(16, len(open_entries))) as pool:
            futures = {pool.submit(_probe_port, host, e["port"]): e for e in open_entries}
            for fut in as_completed(futures):
                entry = futures[fut]
                entry["probes"] = fut.result()
                _refine_service(entry)

    return results, os_info


def _nmap_scan(host: str, ports: list[int]) -> tuple[list[dict], dict]:
    """Targeted service-version scan. Caller passes only already-known-open ports
    so this is fast even on filtered hosts. OS fingerprinting (-O) is intentionally
    omitted: it needs raw sockets (CAP_NET_RAW) which we don't grant in the API
    container. Run the CLI with sudo on bare metal if you need OS detection."""
    port_str = ",".join(str(p) for p in ports)
    cmd = [
        "nmap", "-sV", "--version-intensity", "5", "--open",
        "-T4",                           # aggressive timing template
        "-Pn",                           # don't ping — caller proved the host is up
        "--host-timeout", "60s",
        "-p", port_str, "-oX", "-", host,
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=75).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return [], {}

    results = []
    for m in re.finditer(
        r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>',
        out, re.DOTALL
    ):
        block = m.group(3)
        state_m = re.search(r'<state state="(\w+)"', block)
        svc_m = re.search(
            r'<service name="([^"]*)"'
            r'(?:[^>]*product="([^"]*)")?'
            r'(?:[^>]*version="([^"]*)")?'
            r'(?:[^>]*extrainfo="([^"]*)")?'
            r'(?:[^>]*ostype="([^"]*)")?',
            block,
        )
        cpes = re.findall(r'<cpe>([^<]+)</cpe>', block)
        results.append({
            "port": int(m.group(2)),
            "protocol": m.group(1),
            "state": state_m.group(1) if state_m else "unknown",
            "service": svc_m.group(1) if svc_m else "",
            "product": (svc_m.group(2) if svc_m else "") or "",
            "version": (svc_m.group(3) if svc_m else "") or "",
            "extrainfo": (svc_m.group(4) if svc_m else "") or "",
            "ostype": (svc_m.group(5) if svc_m else "") or "",
            "cpes": cpes,
        })

    # OS fingerprint
    os_info = {}
    osmatch = re.search(
        r'<osmatch name="([^"]+)" accuracy="(\d+)"', out
    )
    if osmatch:
        os_info = {"name": osmatch.group(1), "accuracy": int(osmatch.group(2))}
        osclass = re.search(
            r'<osclass type="([^"]*)" vendor="([^"]*)" osfamily="([^"]*)"'
            r'(?:[^>]*osgen="([^"]*)")?',
            out,
        )
        if osclass:
            os_info.update({
                "type": osclass.group(1),
                "vendor": osclass.group(2),
                "family": osclass.group(3),
                "generation": osclass.group(4) or "",
            })
    return results, os_info


def _socket_scan(host: str, ports: list[int]) -> list[dict]:
    """Concurrent TCP connect scan — one thread per port, bounded pool."""
    def _try(port: int) -> dict | None:
        try:
            with socket.create_connection((host, port), timeout=1.5):
                return {
                    "port": port, "protocol": "tcp", "state": "open",
                    "service": "", "product": "", "version": "",
                }
        except (OSError, socket.timeout):
            return None

    results: list[dict] = []
    if not ports:
        return results
    with ThreadPoolExecutor(max_workers=min(64, len(ports))) as pool:
        for r in pool.map(_try, ports):
            if r is not None:
                results.append(r)
    results.sort(key=lambda r: r["port"])
    return results


# ---------------------------------------------------------------------------
# ICMP timestamp probe (CVE-1999-0524)
# ---------------------------------------------------------------------------
# A host that answers an ICMP Timestamp Request (type 13) with a Timestamp
# Reply (type 14) leaks its system clock — the classic low-severity finding
# vuln scanners report as CVE-1999-0524 (Nessus 10114, Qualys 82003, OpenVAS).
# Raw ICMP send/recv needs a raw socket, which requires elevated privileges
# (root / CAP_NET_RAW on Linux, Administrator on Windows). Without them
# socket() raises PermissionError, which we surface as a clean error field
# rather than a crash — the same reason nmap -O is skipped in the API container.

_ICMP_TIMESTAMP = 13
_ICMP_TIMESTAMP_REPLY = 14


def _icmp_checksum(data: bytes) -> int:
    """RFC 1071 internet checksum. 16-bit words are assembled big-endian so the
    result is byte-order independent when packed back with struct '!H'."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _ms_since_midnight_utc() -> int:
    """ICMP timestamps are milliseconds since midnight UTC, in a 32-bit field."""
    now = datetime.now(timezone.utc)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return int((now - midnight).total_seconds() * 1000) & 0xFFFFFFFF


def _parse_icmp_timestamp_reply(data: bytes, ident: int, seq: int) -> dict | None:
    """Extract the ICMP payload from a received IPv4 packet and return the
    reply's three timestamps, but only if it's a type-14 reply matching the
    identifier/sequence we sent. Returns None for anything else (other ICMP
    traffic can land on the raw socket)."""
    if len(data) < 28:                 # 20-byte min IP header + 8-byte ICMP header
        return None
    ihl = (data[0] & 0x0F) * 4         # IPv4 header length from the IHL nibble
    icmp = data[ihl:]
    if len(icmp) < 20:
        return None
    icmp_type, _code, _chk, r_id, r_seq = struct.unpack("!BBHHH", icmp[:8])
    if icmp_type != _ICMP_TIMESTAMP_REPLY or r_id != ident or r_seq != seq:
        return None
    originate, receive, transmit = struct.unpack("!III", icmp[8:20])
    return {"originate": originate, "receive": receive, "transmit": transmit}


def _icmp_timestamp(host: str, timeout: float = 2.0) -> dict:
    """Send one ICMP Timestamp Request and wait for the reply.

    Never raises. Every failure mode comes back as structured fields:
      supported  — True if it replied, False if it stayed silent, None if we
                   couldn't even ask (no privileges / unresolvable host)
      responded  — bool, convenience mirror of a successful reply
      error/note — human-readable reason when supported is None/False

    On a reply, also reports the disclosed remote clock and its skew from ours.
    """
    try:
        dest = socket.gethostbyname(host)
    except socket.gaierror as e:
        return {"supported": None, "responded": False, "error": f"resolve failed: {e}"}

    ident = os.getpid() & 0xFFFF
    seq = 1
    originate = _ms_since_midnight_utc()

    head = struct.pack("!BBHHH", _ICMP_TIMESTAMP, 0, 0, ident, seq)
    body = struct.pack("!III", originate, 0, 0)
    chk = _icmp_checksum(head + body)
    packet = struct.pack("!BBHHH", _ICMP_TIMESTAMP, 0, chk, ident, seq) + body

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return {
            "supported": None, "responded": False, "host": dest,
            "error": "raw socket denied — run with root / CAP_NET_RAW (Linux) "
                     "or Administrator (Windows)",
        }
    except OSError as e:
        return {"supported": None, "responded": False, "host": dest, "error": str(e)}

    try:
        sent_at = time.monotonic()
        sock.sendto(packet, (dest, 0))
        deadline = sent_at + timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {
                    "supported": False, "responded": False, "host": dest,
                    "note": "no ICMP timestamp reply within timeout — host filters "
                            "type 13 or does not answer",
                }
            if not select.select([sock], [], [], remaining)[0]:
                continue
            data, addr = sock.recvfrom(1024)
            parsed = _parse_icmp_timestamp_reply(data, ident, seq)
            if parsed is None:
                continue  # unrelated ICMP on the raw socket — keep waiting
            our_recv = _ms_since_midnight_utc()
            return {
                "supported": True,
                "responded": True,
                "host": dest,
                "responder": addr[0],
                "rtt_ms": round((time.monotonic() - sent_at) * 1000, 2),
                "originate_ts": originate,
                "receive_ts": parsed["receive"],
                "transmit_ts": parsed["transmit"],
                "clock_skew_ms": parsed["transmit"] - our_recv,
                "cve": "CVE-1999-0524",
            }
    except PermissionError:
        # Windows in particular allows the raw socket to be created but denies
        # sendto/recvfrom (WinError 10013) unless the process is elevated.
        return {
            "supported": None, "responded": False, "host": dest,
            "error": "raw socket send/recv denied — run with root / CAP_NET_RAW "
                     "(Linux) or Administrator (Windows)",
        }
    except OSError as e:
        return {"supported": None, "responded": False, "host": dest, "error": str(e)}
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Generic probes — versatile, not service-specific.
# ---------------------------------------------------------------------------

def _probe_port(host: str, port: int) -> dict:
    """Three generic probes per port, run concurrently. Always store raw
    output so the UI can show whatever came back even with no signature match."""
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_banner = pool.submit(_probe_raw_banner, host, port)
        f_tls = pool.submit(_probe_tls, host, port)
        f_http = pool.submit(_probe_http, host, port)
        return {
            "raw_banner": f_banner.result(),
            "tls": f_tls.result(),
            "http": f_http.result(),
        }


def _probe_raw_banner(host: str, port: int) -> dict | None:
    """Connect, wait for the server to speak first (many do — SSH, FTP, SMTP,
    Redis-INFO, MySQL handshake). If silent, send a generic newline poke."""
    try:
        with socket.create_connection((host, port), timeout=2.0) as s:
            s.settimeout(2.0)
            try:
                data = s.recv(2048)
            except socket.timeout:
                data = b""
            if not data:
                try:
                    s.sendall(b"\r\n\r\n")
                    data = s.recv(2048)
                except (socket.timeout, OSError):
                    data = b""
            if not data:
                return None
            return {
                "bytes": len(data),
                "ascii": data[:512].decode("utf-8", errors="replace"),
                "hex": data[:64].hex(),
            }
    except (OSError, socket.timeout):
        return None


def _probe_tls(host: str, port: int) -> dict | None:
    """Attempt TLS handshake; extract cert subject/issuer/SAN/validity."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=3.0) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert(binary_form=False)
                if not cert:
                    der = s.getpeercert(binary_form=True)
                    return {"present": True, "der_bytes": len(der) if der else 0}
                def _flatten(seq):
                    return {k: v for tup in seq for k, v in tup}
                return {
                    "present": True,
                    "version": s.version(),
                    "cipher": s.cipher(),
                    "subject": _flatten(cert.get("subject", [])),
                    "issuer": _flatten(cert.get("issuer", [])),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
                }
    except (OSError, ssl.SSLError, socket.timeout):
        return None


def _probe_http(host: str, port: int) -> dict | None:
    """Try HTTP GET / on both http and https. Returns the first that responds.
    This is what catches Elasticsearch, Kibana, Jenkins, etc. on any port."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}:{port}/"
        try:
            r = requests.get(url, headers={"User-Agent": _UA},
                             timeout=2.5, verify=False, allow_redirects=False)
            return {
                "scheme": scheme,
                "status_code": r.status_code,
                "headers": dict(r.headers),
                "title": _extract_title(r.text),
                "body_excerpt": r.text[:400],
            }
        except requests.RequestException:
            continue
    return None


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:200] if m else ""


def _refine_service(entry: dict) -> None:
    """Use generic probe output to fill in service/product/version when nmap
    didn't or wasn't available."""
    probes = entry.get("probes", {})

    # Banner regex matching — generic across protocols.
    banner = probes.get("raw_banner")
    if banner and banner.get("ascii"):
        ascii_bytes = banner["ascii"].encode("utf-8", errors="replace")
        for _, pattern, service, ver_group in _BANNER_FINGERPRINTS:
            m = pattern.search(ascii_bytes)
            if m:
                if not entry.get("service"):
                    entry["service"] = service
                if ver_group and not entry.get("version"):
                    try:
                        entry["version"] = m.group(ver_group).decode(errors="replace")
                    except (IndexError, AttributeError):
                        pass
                break

    # HTTP body fingerprinting — catches anything HTTP-speaking on any port.
    http = probes.get("http")
    if http and http.get("body_excerpt"):
        body = http["body_excerpt"]
        for pattern, service in _HTTP_BODY_FINGERPRINTS:
            if pattern.search(body):
                entry["service"] = service
                break
        # Server header is a freebie.
        server = http.get("headers", {}).get("Server")
        if server and not entry.get("product"):
            entry["product"] = server

    # TLS cert subject is also a freebie identity hint.
    tls = probes.get("tls")
    if tls and tls.get("subject", {}).get("commonName") and not entry.get("tls_cn"):
        entry["tls_cn"] = tls["subject"]["commonName"]


def _resolve_url(host: str, port_hint: int | None) -> tuple[str | None, str | None]:
    """Find a working URL for `host` by probing candidate scheme/port combos
    in parallel. Returns (url, origin) of the first one that responds, or
    (None, None) if nothing answers. Used when the caller passes a bare IP
    or hostname instead of a full URL — there's nothing magic about a URL,
    we just need *some* URL to hit, and we can construct one."""
    candidates: list[str] = []
    if port_hint:
        candidates += [f"https://{host}:{port_hint}", f"http://{host}:{port_hint}"]
    candidates += [f"https://{host}", f"http://{host}"]
    # de-dupe while preserving order
    seen: set[str] = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]

    def _probe(origin: str) -> str | None:
        try:
            r = requests.get(origin + "/", headers={"User-Agent": _UA},
                             timeout=3, verify=False, allow_redirects=False)
            if r.status_code:
                return origin
        except requests.RequestException:
            return None
        return None

    with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
        futures = {pool.submit(_probe, c): c for c in candidates}
        # Walk in submission order so https-on-standard-port wins ties.
        for c in candidates:
            for fut, origin in futures.items():
                if origin == c and fut.result() is not None:
                    return origin + "/", origin
    return None, None


def _sanitize_location(value: str, base: str) -> str:
    """Pick the first valid Location URL, even if the server sent multiple
    Location headers (urllib3 joins them with ', ' which requests then tries
    to follow as one giant URL — Cloudflare's 1.1.1.1 redirect does this).
    Also resolves relative redirects against the current URL."""
    if not value:
        return ""
    # First Location wins; trailing entries are almost always duplicates.
    first = value.split(",")[0].strip()
    if first.startswith(("http://", "https://")):
        return first
    return urljoin(base, first)


def _http_analysis(target: str) -> dict:
    """Manually follow redirects so we can sanitize malformed Location headers
    instead of letting requests build a corrupt final URL."""
    session = requests.Session()
    headers = {"User-Agent": _UA}
    redirect_chain: list[dict] = []
    current = target
    resp = None

    try:
        for _ in range(10):  # cap redirects
            resp = session.get(current, headers=headers, timeout=15,
                               allow_redirects=False, verify=False)
            if 300 <= resp.status_code < 400 and resp.headers.get("Location"):
                redirect_chain.append({"url": current, "status_code": resp.status_code})
                current = _sanitize_location(resp.headers["Location"], current)
                if not current:
                    break
                continue
            break
    except requests.RequestException as e:
        return {"error": str(e)}

    if resp is None:
        return {"error": "no response"}

    cookies = []
    for c in resp.cookies:
        cookies.append({
            "name": c.name,
            "httponly": c.has_nonstandard_attr("HttpOnly") or getattr(c, "_rest", {}).get("HttpOnly") is not None,
            "secure": bool(c.secure),
            "samesite": c._rest.get("SameSite", "") if hasattr(c, "_rest") else "",
            "path": c.path,
            "domain": c.domain,
        })

    return {
        "status_code": resp.status_code,
        "final_url": current,
        "redirect_chain": redirect_chain,
        "headers": dict(resp.headers),
        "cookies": cookies,
        "body": resp.text,
    }


def _fingerprint(http: dict) -> list[dict]:
    seen: set[str] = set()
    techs: list[dict] = []

    def add(name, category, confidence):
        if name not in seen:
            seen.add(name)
            techs.append({"name": name, "category": category, "confidence": confidence})

    headers = http.get("headers", {})
    header_blob = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    body = http.get("body", "")

    for pattern, name, category in _HEADER_FINGERPRINTS:
        if re.search(pattern, header_blob, re.IGNORECASE):
            add(name, category, "high")

    for pattern, name, category in _HTML_FINGERPRINTS:
        if re.search(pattern, body, re.IGNORECASE):
            add(name, category, "medium")

    # Security header audit
    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing Protection",
        "Referrer-Policy": "Referrer Policy",
        "Permissions-Policy": "Permissions Policy",
    }
    missing = [label for hdr, label in security_headers.items() if hdr not in headers]
    if missing:
        techs.append({
            "name": "Missing Security Headers",
            "category": "Security",
            "confidence": "high",
            "detail": missing,
        })

    return techs


def _content_analysis(target: str, origin: str, body: str) -> dict:
    forms = []
    for m in re.finditer(r'<form([^>]*)>(.*?)</form>', body, re.DOTALL | re.IGNORECASE):
        attrs = m.group(1)
        inner = m.group(2)
        action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', inner, re.IGNORECASE)
        action = action_m.group(1) if action_m else ""
        forms.append({
            "action": urljoin(target, action) if action else target,
            "method": (method_m.group(1) if method_m else "get").upper(),
            "inputs": inputs,
        })

    links = list({
        urljoin(origin, href)
        for href in re.findall(r'href=["\']([^"\'#?][^"\']*)["\']', body, re.IGNORECASE)
        if not href.startswith(("http://", "https://")) or href.startswith(origin)
    })[:50]

    emails = list(set(re.findall(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', body
    )))

    js_files = list({
        (urljoin(origin, src) if not src.startswith("http") else src)
        for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
    })

    comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
    interesting_comments = [c.strip() for c in comments if len(c.strip()) > 5][:10]

    return {
        "forms": forms,
        "internal_links": links,
        "emails": emails,
        "js_files": js_files,
        "html_comments": interesting_comments,
    }


def _well_known(origin: str) -> dict:
    paths = {
        "robots_txt": "/robots.txt",
        "sitemap_xml": "/sitemap.xml",
        "security_txt": "/.well-known/security.txt",
    }
    headers = {"User-Agent": _UA}

    def _fetch(item: tuple[str, str]) -> tuple[str, dict]:
        key, path = item
        url = origin + path
        try:
            r = requests.get(url, headers=headers, timeout=5)
            return key, {
                "url": url,
                "status_code": r.status_code,
                "content": r.text[:2000] if r.status_code == 200 else None,
            }
        except requests.RequestException:
            return key, {"url": url, "status_code": None, "content": None}

    with ThreadPoolExecutor(max_workers=len(paths)) as pool:
        return dict(pool.map(_fetch, paths.items()))
