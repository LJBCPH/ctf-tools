# CTF Winner - Claude Code Guidelines

## Project Overview

CTF (Capture the Flag) challenge solver project. Use autonomous Ralph Wiggum loops to iterate on solutions.

## Ralph Wiggum Setup

> Already done on this machine. Follow these steps on a new machine.

### 1. Install jq (required dependency)

```bash
# Windows (winget)
winget install jqlang.jq

# macOS
brew install jq

# Linux
sudo apt install jq  # or: sudo dnf install jq
```

Restart your terminal after installing so `jq` is in PATH.

### 2. Install the plugin

Run these two commands inside a Claude Code session:

```
/plugin marketplace add anthropics/claude-code
/plugin install ralph-wiggum@claude-plugins-official
```

Alternatively, clone the repo and copy the plugin directory manually:

```bash
git clone https://github.com/anthropics/claude-code.git /tmp/cc
cp -r /tmp/cc/plugins/ralph-wiggum ~/.claude/plugins/
chmod +x ~/.claude/plugins/ralph-wiggum/hooks/stop-hook.sh
chmod +x ~/.claude/plugins/ralph-wiggum/scripts/setup-ralph-loop.sh
```

### 3. Register the stop hook

Add this to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash \"$HOME/.claude/plugins/ralph-wiggum/hooks/stop-hook.sh\""
          }
        ]
      }
    ]
  },
  "plugins": [
    {
      "name": "ralph-wiggum",
      "path": "$HOME/.claude/plugins/ralph-wiggum"
    }
  ]
}
```

### 4. Restart Claude Code

The plugin and hook only load on startup. Restart after any settings change.

### 5. Verify

Run `/ralph-loop --help` inside Claude Code — if it shows usage info, you're good.

---

## Ralph Wiggum Loop Usage

This project is set up for autonomous iterative development using the Ralph Wiggum plugin.

### Quick Start

```
/ralph-loop "Your task here" --max-iterations 20 --completion-promise "DONE"
```

### When to Use Ralph Loops

- Solving CTF challenges where you need to iterate on exploits/solutions
- Running tests repeatedly until they pass
- Refactoring until a target metric is met
- Any task with clear, verifiable success criteria

### Writing Good Prompts

Prompts must include **explicit, verifiable completion criteria**. Ralph cannot judge "good enough" — it needs something concrete to check.

**Template:**
```
[Task description with specific requirements]

Success criteria:
- [Criterion 1 — something you can verify with a tool or command]
- [Criterion 2]

When ALL criteria are met, output: <promise>DONE</promise>
```

**CTF Example:**
```
/ralph-loop "
Solve the binary exploitation challenge in ./challenge/vuln.
Requirements:
- Identify the vulnerability (buffer overflow, format string, etc.)
- Write a working exploit in ./exploit.py
- Running 'python exploit.py' must produce the flag
- Flag format: CTF{...}

When exploit produces the flag, output: <promise>EXPLOIT COMPLETE</promise>
" --max-iterations 30 --completion-promise "EXPLOIT COMPLETE"
```

### Safety Rules

1. **Always set `--max-iterations`** — prevents runaway API costs. Use 10–30 for most tasks.
2. **Use git before starting** — each iteration modifies files. Commit or stash first.
3. **Verifiable promises only** — the completion promise must be something objectively true.
4. **Monitor with:** `head -10 .claude/ralph-loop.local.md` to check iteration count.

### Cancelling a Loop

```
/cancel-ralph
```

Or delete the state file directly:
```bash
rm .claude/ralph-loop.local.md
```

### Iteration Limits by Task Type

| Task | Recommended `--max-iterations` |
|------|-------------------------------|
| Simple bug fix | 5–10 |
| CTF challenge (easy) | 10–20 |
| CTF challenge (hard) | 20–50 |
| Refactoring with tests | 10–20 |
| New feature with TDD | 15–30 |

## General Guidelines

- Always work in a git-tracked directory (initialize with `git init` if needed)
- Prefer running tools/tests over asking for feedback — let the output drive iteration
- When stuck, document what was tried before hitting `--max-iterations`
