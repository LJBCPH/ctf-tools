# CTF Winner - Claude Code Guidelines

## Project Overview

CTF (Capture the Flag) challenge solver project. Use autonomous Ralph Wiggum loops to iterate on solutions.

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
