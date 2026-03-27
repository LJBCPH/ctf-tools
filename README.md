# ctf-tools

A CLI toolkit for CTF challenges. Wraps common tools (nmap, dirb, ffuf) and adds custom modules for web recon and password attacks.

## Installation (WSL)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

The `ctf` command is now available inside the venv. 
---

## Commands

### `ctf password crack`

Brute forces a web login. Auto-discovers the login endpoint from the site's JS bundle.

```bash
ctf password crack -t <url> -u <email> [options]

Options:
  -t  Target URL (site root or full endpoint)
  -u  Username / email
  -w  Wordlist          (default: wordlists/john_password.lst)
  -p  Line range        e.g. -p 4000-4100
  -P  Parallel workers  (default: 10)
  -r  Fail HTTP code    (default: 401)
  -o  Save hits to file
  -v  Verbose output
```

```bash
# Auto-discover endpoint and attack
ctf password crack -t https://example.com -u admin@example.com

# Specific line range, 20 parallel
ctf password crack -t https://example.com -u admin@example.com -p 4000-4100 -P 20
```

---

### `ctf password sqli`

Tests a login endpoint for SQL injection bypass. Auto-discovers the endpoint from the JS bundle. Tries payloads in the password field, email field, and both simultaneously.

```bash
ctf password sqli -t <url> [options]

Options:
  -t  Target URL (site root or full endpoint)
  -u  Fix the username/email and only inject into the password field
  -r  Fail HTTP code (default: 401)
  -o  Save hits to file
  -v  Verbose — print every attempt
```

```bash
# Try all payloads (email + password fields)
ctf password sqli -t https://example.com

# Fix the user, only inject into password
ctf password sqli -t https://example.com -u admin@example.com -v
```

---

### `ctf web discover`

Fetches JS bundles from a React/SPA site and lists all API endpoints and emails found.

```bash
ctf web discover -t https://example.com
```

---

### `ctf web dirb`

Runs `dirb` directory brute force. Extra args are passed through to dirb.

```bash
ctf web dirb -t https://example.com
ctf web dirb -t https://example.com -x php,html
```

---

### `ctf web fuzz`

Runs `ffuf`. Use `FUZZ` as a placeholder in the URL.

```bash
ctf web fuzz -t "https://example.com/page?id=FUZZ" -w wordlists/john_password.lst -fc 404
```

---

### `ctf recon nmap`

Runs nmap. Common flags are exposed as options; anything extra is passed through.

```bash
ctf recon nmap -t 10.0.0.1
ctf recon nmap -t 10.0.0.1 -sV -sC --top 100
ctf recon nmap -t 10.0.0.1 -p 1-65535 -o scan.txt
ctf recon nmap -t 10.0.0.1 -- -T4 --script vuln   # pass raw nmap args after --
```

---

### `ctf recon whois`

```bash
ctf recon whois -t example.com
```

---

### `ctf recon headers`

Fetches and prints HTTP response headers.

```bash
ctf recon headers -t https://example.com
```

---

## Dependencies

External tools are called via subprocess. Install what you need:

```bash
sudo apt install nmap dirb ffuf
```

The CLI will print the install command if a tool is missing.

## Wordlists

| File | Description |
|------|-------------|
| `wordlists/john_password.lst` | John the Ripper default list (~1.8M passwords) |

---

## Adding New Tools

1. Add a new function (or group) to the relevant file in `ctf/`
2. Or create a new file and register it in `ctf/main.py`
