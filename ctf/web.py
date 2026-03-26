import re
import shutil
import subprocess
import sys
import click
import requests
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

WORDLISTS_DIR = Path(__file__).parent.parent / "wordlists"
DEFAULT_DIRB_WORDLIST = "/usr/share/dirb/wordlists/common.txt"


@click.group()
def web():
    """Web recon & enumeration — discover, dirb, fuzz."""
    pass


@web.command()
@click.option("-t", "--target", required=True, help="Target URL")
def discover(target):
    """Auto-discover login endpoints, emails, and API routes from JS bundles."""
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    origin = re.match(r"https?://[^/]+", target).group()

    console.print(f"[cyan][*][/cyan] Fetching [bold]{target}[/bold]...")
    try:
        html = requests.get(target, headers=headers, timeout=10).text
    except requests.RequestException as e:
        console.print(f"[red][!] {e}[/red]")
        sys.exit(1)

    js_srcs = re.findall(r'src="([^"]+\.js)"', html)
    if not js_srcs:
        console.print("[yellow][!] No JS bundles found.[/yellow]")
        sys.exit(1)

    all_endpoints = []
    all_emails = []

    for src in js_srcs:
        bundle_url = src if src.startswith("http") else f"{origin}{src}"
        console.print(f"[dim]  Scanning {bundle_url}[/dim]")

        try:
            bundle = requests.get(bundle_url, headers=headers, timeout=15).text
        except requests.RequestException:
            console.print(f"[yellow]  [!] Failed to fetch bundle[/yellow]")
            continue

        # API base
        api_base = ""
        m = re.search(r'["\`](/api[^"\`]{0,10})["\`]', bundle)
        if m:
            api_base = m.group(1)

        # All API calls
        for method in ["get", "post", "put", "patch", "delete"]:
            paths = re.findall(rf'{method}\(["\`](/[^"\`]{{1,80}})["\`]', bundle)
            for path in paths:
                all_endpoints.append((method.upper(), f"{origin}{api_base}{path}"))

        # Emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', bundle)
        all_emails += [e for e in emails if "example" not in e and "test" not in e]

    # Print results
    if all_endpoints:
        table = Table(title="Discovered Endpoints", show_lines=True)
        table.add_column("Method", style="bold cyan", width=8)
        table.add_column("URL", style="white")
        seen = set()
        for method, url in all_endpoints:
            if url not in seen:
                seen.add(url)
                color = {"POST": "yellow", "GET": "green", "DELETE": "red"}.get(method, "white")
                table.add_row(f"[{color}]{method}[/{color}]", url)
        console.print(table)

    if all_emails:
        console.print(f"\n[green][+][/green] Emails found: {', '.join(set(all_emails))}")

    if not all_endpoints and not all_emails:
        console.print("[yellow][-] Nothing found.[/yellow]")


@web.command()
@click.option("-t", "--target", required=True, help="Target URL to enumerate")
@click.option("-w", "--wordlist", default=DEFAULT_DIRB_WORDLIST, show_default=True, help="Wordlist for dirb")
@click.option("-x", "--extensions", default=None, help="Extensions to append, e.g. php,html")
@click.argument("extra", nargs=-1)
def dirb(target, wordlist, extensions, extra):
    """Run dirb directory brute force on the target. Extra args are passed through."""
    _require_tool("dirb")

    cmd = ["dirb", target, wordlist]
    if extensions:
        cmd += ["-X", extensions]
    cmd += list(extra)

    console.print(f"[cyan][*][/cyan] Running: [bold]{' '.join(cmd)}[/bold]\n")
    subprocess.run(cmd)


@web.command()
@click.option("-t", "--target", required=True, help="Target URL with FUZZ placeholder")
@click.option("-w", "--wordlist", required=True, help="Wordlist file")
@click.option("-fc", "--filter-code", default=None, help="Hide responses with this HTTP code, e.g. 404")
@click.argument("extra", nargs=-1)
def fuzz(target, wordlist, filter_code, extra):
    """Run ffuf fuzzer. Use FUZZ as placeholder in the target URL."""
    _require_tool("ffuf")

    cmd = ["ffuf", "-u", target, "-w", wordlist]
    if filter_code:
        cmd += ["-fc", filter_code]
    cmd += list(extra)

    console.print(f"[cyan][*][/cyan] Running: [bold]{' '.join(cmd)}[/bold]\n")
    subprocess.run(cmd)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_tool(name: str):
    if not shutil.which(name):
        console.print(f"[red][!] '{name}' not found. Install it first:[/red]")
        console.print(f"    [dim]sudo apt install {name}[/dim]")
        sys.exit(1)
