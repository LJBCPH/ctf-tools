import shutil
import subprocess
import sys
import click
from rich.console import Console

console = Console()


@click.group()
def recon():
    """Reconnaissance — nmap, whois, headers."""
    pass


@recon.command()
@click.option("-t", "--target", required=True, help="Target host or IP")
@click.option("-p", "--ports", default=None, help="Port range, e.g. 80,443 or 1-1000")
@click.option("--top", default=None, type=int, help="Scan top N ports")
@click.option("-sV", "service_version", is_flag=True, help="Service/version detection")
@click.option("-sC", "default_scripts", is_flag=True, help="Run default scripts")
@click.option("-A", "aggressive", is_flag=True, help="Aggressive scan (-A)")
@click.option("-o", "--output", default=None, help="Save output to file")
@click.argument("extra", nargs=-1)
def nmap(target, ports, top, service_version, default_scripts, aggressive, output, extra):
    """Run nmap against the target. Extra args are passed through to nmap."""
    _require_tool("nmap")

    cmd = ["nmap", target]
    if ports:
        cmd += ["-p", ports]
    if top:
        cmd += [f"--top-ports", str(top)]
    if service_version:
        cmd.append("-sV")
    if default_scripts:
        cmd.append("-sC")
    if aggressive:
        cmd.append("-A")
    if output:
        cmd += ["-oN", output]
    cmd += list(extra)

    console.print(f"[cyan][*][/cyan] Running: [bold]{' '.join(cmd)}[/bold]\n")
    subprocess.run(cmd)


@recon.command()
@click.option("-t", "--target", required=True, help="Domain or IP to look up")
def whois(target):
    """Run whois lookup on the target."""
    _require_tool("whois")
    console.print(f"[cyan][*][/cyan] whois [bold]{target}[/bold]\n")
    subprocess.run(["whois", target])


@recon.command()
@click.option("-t", "--target", required=True, help="Target URL")
def headers(target):
    """Fetch and display HTTP response headers."""
    import requests
    console.print(f"[cyan][*][/cyan] Fetching headers from [bold]{target}[/bold]\n")
    try:
        resp = requests.head(target, timeout=10, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0"})
        for k, v in resp.headers.items():
            console.print(f"  [bold cyan]{k}[/bold cyan]: {v}")
        console.print(f"\n  [dim]Status: {resp.status_code}[/dim]")
    except requests.RequestException as e:
        console.print(f"[red][!] {e}[/red]")
        sys.exit(1)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_tool(name: str):
    if not shutil.which(name):
        console.print(f"[red][!] '{name}' not found. Install it first:[/red]")
        console.print(f"    [dim]sudo apt install {name}[/dim]")
        sys.exit(1)
