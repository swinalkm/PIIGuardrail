# PII Guardrail

**A credential filter for Claude Code.** It keeps API keys, tokens, and private keys out of the
model's context when you read a file or run a command that contains them — without blocking the
work.

> **Status: in development.** The design and the platform contract are verified; the
> implementation is not finished. Do not install this expecting it to protect you yet.

```
you:     "why is the DB connection failing?"
claude:  reads .env

         without this plugin  →  DATABASE_URL=postgres://admin:hunter2@db.prod:5432/app
         with this plugin     →  DATABASE_URL=[[DB_URI_1]]
```

Claude still sees that a `DATABASE_URL` exists and can still debug your connection. It just never
sees `hunter2`.

---

## Why

Reading `.env` files and running `env` is something you do with Claude constantly without thinking
about it. Every time, live credentials land in a transcript that leaves your machine and may be
cached or retained. This plugin makes that specific, extremely common event harmless.

## Install

```
/plugin marketplace add <your-github-username>/PIIGuardrail
/plugin install piiguard@piiguard
```

That's it. It works immediately with no configuration.

## Requirements

- Claude Code
- `python3` on your `PATH`

**No Python packages.** The scanner is stdlib-only — no pip, no lockfile, no supply-chain surface.
For a tool that runs on every prompt, that's a deliberate feature, and it means you can audit the
entire thing by reading one directory.

If `python3` is missing, the plugin disables itself silently and warns you once. It never breaks
your session.

---

## How it works

Three separate paths, and they have **different capabilities**. That difference is the most
important thing to understand about this plugin.

### 1. Tool output — the main feature

1. Claude runs a tool (`Read`, `Bash`, `Grep`). **It runs normally** — nothing is blocked.
2. Before the result reaches the model, the plugin scans it.
3. Credentials are replaced with labels: `AKIAIOSFODNN7EXAMPLE` → `[[AWS_ACCESS_KEY_1]]`.
4. The model receives the cleaned version. Variable names survive; values don't.

Redaction happens *after* execution, which is why `cat .env` still works normally for you.

### 2. Prompts you type — block only

1. You submit a prompt.
2. The plugin scans it before it is sent.
3. If it contains a credential, **the prompt is blocked** and you're told why. Nothing is sent.
4. You edit it and resend.

**It cannot clean a prompt.** Claude Code has no mechanism for rewriting prompt text — only for
blocking it. So for anything you type, it's all-or-nothing. See
[Limitations](#limitations-read-this).

### 3. Writes to disk — asks first

If Claude is about to `Write` or `Edit` a file whose content contains a live credential, you get a
permission prompt naming what was found. You approve or reject. The plugin never decides for you.

---

## What it detects

### On by default — Tier 1

High-confidence formats where the structure itself is the evidence, so false positives are rare.

| Class | What it matches |
|---|---|
| `AWS_ACCESS_KEY` | `AKIA` + 16 chars, plus paired secret keys by entropy |
| `GITHUB_TOKEN` | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` + 36 chars |
| `ANTHROPIC_KEY` | `sk-ant-…` |
| `SLACK_TOKEN` | `xoxb-` / `xoxp-` / `xoxa-` / `xoxr-` / `xoxs-` |
| `PRIVATE_KEY` | PEM `BEGIN … PRIVATE KEY` blocks |
| `JWT` | Three-part tokens whose header actually decodes to JSON |
| `DB_URI` | `scheme://user:password@host` with a real password |
| `CREDIT_CARD` | 13–19 digits passing Luhn and a known IIN range |

Well-known test card numbers (`4242…`, `4111…`) are **not** redacted — payment-integration work
keeps working.

### Off by default — Tier 2

These are implemented but disabled, because in a coding context they are overwhelmingly false
positives and redacting them breaks your work:

| Class | Why it's off |
|---|---|
| `EMAIL` | `git log`, `git blame`, `CODEOWNERS`, `package.json`. Redact these and `git blame` becomes useless |
| `IP_ADDRESS` | `127.0.0.1`, Docker bridges, k8s service CIDRs — almost never personal data |
| `DOB` | Any `YYYY-MM-DD` in a changelog or migration filename |
| `PHONE` | Version strings and IDs match readily |
| `GENERIC_SECRET` | Matches git SHAs, lockfile hashes, UUIDs, minified JS, and every `token = "..."` in a test file |

Enable them per-class if your work genuinely involves personal data:

```json
{ "classes": ["AWS_ACCESS_KEY", "PRIVATE_KEY", "EMAIL", "PHONE"] }
```

---

## Configuration

Optional. Edit `${CLAUDE_PLUGIN_DATA}/policy.json` — it is seeded on first run and **survives
plugin updates**.

```json
{
  "mode": "guard",
  "classes": ["AWS_ACCESS_KEY", "GITHUB_TOKEN", "ANTHROPIC_KEY",
              "SLACK_TOKEN", "PRIVATE_KEY", "JWT", "DB_URI", "CREDIT_CARD"],
  "audit": true
}
```

| Setting | Values | Meaning |
|---|---|---|
| `mode` | `guard` | Redact, block, and ask. The default |
| | `detect` | Never modify or block anything; only log. Good for a trial run |
| | `off` | Fully inert |
| `classes` | list | Which detectors are active |
| `audit` | bool | Write to the audit log |

## The audit log

`${CLAUDE_PLUGIN_DATA}/audit.jsonl`, one line per event:

```json
{"ts":"2026-09-16T10:04:21Z","event":"PostToolUse","tool":"Read",
 "action":"redact","hits":[{"class":"AWS_ACCESS_KEY","id":"9f2ac41b7e05"}]}
```

`id` is `HMAC-SHA256(per-install random salt, value)`, truncated. **The secret is never written to
the log**, and a plain hash isn't used either — `sha256` of a card number or a date of birth is
brute-forceable in seconds. The HMAC lets you count distinct values without creating a crackable
store of the things you were trying to protect.

Only events that were acted on are logged. A log full of `127.0.0.1` would train you to ignore it.

## Privacy

Nothing is transmitted. No telemetry, no error reporting, no network calls of any kind. The policy
file, the salt, and the audit log all stay in `${CLAUDE_PLUGIN_DATA}` on your machine. The author
of this plugin receives nothing and can see nothing.

The flip side: there's no feedback channel, so if it misses something, please open an issue.

---

## Limitations — read this

This is harm reduction for a common accident. It is **not** a security boundary.

**It is not a compliance control.** Not GDPR, PCI-DSS, HIPAA, SOC 2, or DLP tooling. Do not
represent it as one to an auditor.

**It does not protect what you type.** Prompts can only be blocked, not cleaned — Claude Code
offers no mechanism to rewrite prompt text. Anything you paste is sent verbatim unless the whole
message is blocked.

**It does not catch names, addresses, or contextual disclosure.** "My daughter goes to St Xaviers
in Pune" is invisible to it. Detection is regex plus validators — it recognises *formats*, not
meaning. Realistic recall on free-form prose is roughly **60–70%**; on structured credentials it is
much higher.

**It cannot un-send.** Only the current turn is filtered. Anything already in your transcript from
earlier turns stays there, and existing transcript files on disk are not scrubbed.

**Another plugin can silently defeat it.** `PostToolUse` hooks run in parallel and the last write
wins. If you also run a hook that rewrites tool output — log compressors and output truncators are
the common ones — it may overwrite this plugin's redaction, re-exposing the secret with no warning.
This plugin never emits an unchanged rewrite, to avoid clobbering others in the same way.

**It assumes a cooperative path.** It is not a defence against prompt injection, a malicious model,
or deliberate exfiltration. Someone who wants to leak a secret can trivially do so.

**It does not scan commits.** Use [gitleaks](https://github.com/gitleaks/gitleaks) or a pre-commit
hook for that — different problem, better-solved elsewhere.

**Detection rates are not yet measured.** Per-class precision and recall will be published here
once the corpus harness runs. Until then, treat coverage as unproven.

---

## Development

```bash
git clone https://github.com/<your-github-username>/PIIGuardrail
cd PIIGuardrail
python3 -m unittest discover tests/          # no dependencies to install
```

Test it against a local checkout before publishing:

```
/plugin marketplace add ./
/plugin install piiguard@piiguard
```

### Design notes

- **Fail open, loudly.** Any internal error exits cleanly and warns on stderr. A crash must never
  break someone's session, and it must never be mistaken for a deliberate block. A silently failing
  security tool is worse than none — it manufactures false confidence.
- **Rewrites preserve structure.** Replacement tool output is validated against each tool's schema,
  so only string values are ever substituted; keys and types are untouched.
- **Bounded work.** Python's `re` has no timeout, so inputs above 1 MB fall back to anchored
  patterns only, long lines are skipped, and the hook has a hard 5-second timeout.

Architecture and diagrams: [docs/WORKFLOW.md](docs/WORKFLOW.md).

## Contributing

Detectors are declarative — adding one is a pattern, a validator, and corpus entries. A new
detector needs test cases covering both what it should catch and what it must *not*.

The bar for Tier 1 is deliberately high: near-zero false positives on real codebases. When in
doubt, propose it as Tier 2.

## License

MIT
