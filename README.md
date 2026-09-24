# PII Guardrail

**Scans your prompt before it reaches Claude.** If it contains something from your secrets list,
the prompt is blocked and you're told what was found. If it's clean, it goes through untouched.

> **Status: v0.2.0 — 17 detectors implemented.** Working end to end. Detection rates
> are not yet formally measured; see [Limitations](#limitations--read-this).

```
you:  "email the report to carol@acme.io"

      ⛔ PII Guardrail blocked this message
         Found: EMAIL (1 occurrence)
         Nothing was sent. Remove the value and send again.

you:  "email the report to the address in contacts.csv"

      ✅ sent
```

---

## Where this works

This is a **Claude Code plugin**. It protects Claude Code and nothing else.

| Surface | Protected | Why |
|---|---|---|
| Claude Code — terminal | ✅ | Plugin hooks run locally before each prompt |
| Claude Code — VS Code / JetBrains | ✅ | Same hooks |
| Subagents & background tasks | ✅ | Hooks apply to them too |
| **claude.ai web UI** | ❌ | No plugin system. Your prompt goes browser → Anthropic with nothing local in between |
| **Claude Desktop / mobile** | ❌ | No plugin mechanism exists |
| **Anthropic API / your own agents** | ❌ | Your code calls the API directly, bypassing Claude Code entirely |

**Scope is deliberately limited to Claude Code.** Covering the other surfaces would mean separate
products — a browser extension, an API proxy — and those are not planned. If you paste a secret
into claude.ai, nothing here will stop you.

---

## Install

**Requires:** Claude Code, and `python3` on your `PATH`.

**No Python packages** — the scanner is stdlib-only. No pip, no lockfile, no
supply-chain surface. The whole thing is one directory you can read before trusting it.

If `python3` is missing, the plugin disables itself and warns you once. It never breaks
a session.

### From GitHub

```bash
claude plugin marketplace add https://github.com/swinalkm/PIIGuardrail.git
claude plugin install piiguard@piiguard
```

Inside the Claude Code **terminal** you can use the slash-command equivalents:

```
/plugin marketplace add https://github.com/swinalkm/PIIGuardrail.git
/plugin install piiguard@piiguard
```

> `/plugin` is only available in the terminal. In the VS Code and JetBrains
> extensions it returns *"`/plugin` isn't available in this environment"* — use the
> `claude plugin ...` commands above from any shell instead. They do the same thing.

**Both steps are required.** `install` can only resolve a marketplace that has already
been added — running it alone gives `Marketplace "piiguard" not found`.

**Restart Claude Code afterwards.** Hooks are loaded at session start.

### From a local clone

```bash
git clone https://github.com/swinalkm/PIIGuardrail.git
cd PIIGuardrail
claude plugin marketplace add "$PWD"
claude plugin install piiguard@piiguard
```

### Verify

```bash
claude plugin list                    # should show piiguard@piiguard, enabled
```

Then restart Claude Code and send a message containing an email address. It should be
blocked before it is sent.

### Updating

```bash
cd PIIGuardrail && git pull
claude plugin marketplace update piiguard
```

Your `secrets.txt`, audit log, and salt live outside the repo and are never touched by
an update.

### Uninstalling

```bash
claude plugin disable piiguard@piiguard      # stop it running, keep it installed
claude plugin uninstall piiguard@piiguard    # remove the plugin
claude plugin marketplace remove piiguard    # deregister the marketplace
```

---

## Turning it on and off

Three levels, from quickest to most thorough.

### 1. Toggle the guard — instant, no restart

```
/piiguard off        # stop blocking and redacting
/piiguard on         # resume
/piiguard detect     # log detections but never block
/piiguard status     # what is it doing right now
```

Or from a terminal:

```bash
"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" --off
"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" --status
```

```
PII Guardrail v0.2.0
  status   : ON  (blocking and redacting)
  detectors: 12 active
  config   : /Users/you/.../piiguard/secrets.txt
  watching : anthropic_key, aws_access_key, db_uri, email, github_token, ...
  detections logged: 14
```

The hook re-reads config on every invocation, so the change applies to your very next
prompt.

**`detect` is the useful middle setting** — it records everything it *would* have
caught without ever interrupting you. Run it for a week, read the audit log, then
decide whether to switch on.

### 2. Turn off one category

Comment out a line in `${CLAUDE_PLUGIN_DATA}/secrets.txt`:

```sh
aws_access_key
# email          ← now ignored
```

### 3. Disable the plugin entirely

```bash
claude plugin disable piiguard@piiguard      # needs a restart
```

| | Effect | Restart? |
|---|---|---|
| `/piiguard off` | Hook runs, does nothing | No |
| Comment out a line | That one category stops | No |
| `plugin disable` | Hook never runs | Yes |

---


## The secrets file

One file controls everything. It lives at `${CLAUDE_PLUGIN_DATA}/secrets.txt`, is created on first
run, and **survives plugin updates**.

```sh
# ── categories ────────────────────────────────
email

# ── literal values ────────────────────────────
# Exact strings blocked wherever they appear.
"acme-internal.corp"

# ── custom patterns ───────────────────────────
# Your own regex, between slashes.
/EMP-[0-9]{6}/

# ── allowlist ─────────────────────────────────
# Never flag anything containing these.
!example.com
```

Four entry types:

| Syntax | Meaning |
|---|---|
| `email` | Enable a built-in detector |
| `"literal"` | Block this exact string, anywhere |
| `/regex/` | Block anything matching your pattern |
| `!text` | Allowlist — never flag anything containing this |

Edit the file, and the next prompt uses it. No restart.

### Built-in categories

**On by default** — high confidence, because the format itself is the evidence:

| Category | Matches |
|---|---|
| `aws_access_key` | `AKIA`/`ASIA`/`AROA`… + 16 chars |
| `aws_secret_key` | 40-char secret in an `aws_secret_access_key=` assignment |
| `github_token` | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` + 36 |
| `anthropic_key` | `sk-ant-…` |
| `openai_key` | `sk-…` / `sk-proj-…` |
| `slack_token` | `xoxb-` / `xoxp-` / `xoxa-` / `xoxr-` / `xoxs-` |
| `google_api_key` | `AIza` + 35 chars |
| `stripe_key` | `sk_live_` / `sk_test_` / `rk_live_` / `rk_test_` |
| `jwt` | Three-part token whose header **base64-decodes to JSON with an `alg`** |
| `private_key` | PEM `BEGIN … PRIVATE KEY` blocks (line count preserved) |
| `db_uri` | `scheme://user:password@host`, placeholder passwords ignored |
| `email` | Email addresses |

**Off by default** — correct, but noisy in a coding context. Uncomment in `secrets.txt`:

| Category | Why it's off |
|---|---|
| `credit_card` | Luhn + issuer prefix, test cards excluded — but long numeric IDs can still collide |
| `phone` | Version strings and numeric IDs resemble phone numbers |
| `ip_address` | Public only (loopback, RFC1918, multicast skipped) — but CDN and cloud IPs in logs match |
| `dob` | Any ISO or DD/MM/YYYY date — changelogs, migration filenames, fixtures |
| `generic_secret` | `token = "..."` assignments — also matches git SHAs, lockfile hashes, UUIDs |

### What the validators throw away

Every pattern is paired with a check, which is what keeps this usable. Verified against real
developer content — these are **not** flagged:

```
sha512-Xk29fLpQw81ZmRtVb04YnSeAqWc7Zx0PlmNbVv==     lockfile hash
550e8400-e29b-41d4-a716-446655440000               UUID
4242424242424242                                   test card
127.0.0.1  192.168.1.5  10.96.0.1                  private IPs
postgres://user:password@localhost:5432/db         placeholder password
Authorization: Bearer YOUR_TOKEN_HERE              placeholder token
5432  8080  1099511627776                          ports and numbers
```

**Known noise:** with `email` on, `git log`, `git blame`, `CODEOWNERS` and `package.json` author
fields all get redacted in tool output. If that gets in your way, allowlist your team's domain
(below) or comment out `email`.

### Allowlisting

Lines starting with `!` are never flagged. Useful for test domains and your own address:

```sh
email
!example.com
!noreply.github.com
```

---

## What happens, step by step

### Your prompt — blocked

1. You submit a prompt.
2. The plugin scans it against your secrets file.
3. **Nothing found** → sent normally. This is the common case.
4. **Something found** → the prompt is **blocked** and you're shown what matched.
5. You edit it and resend.

⚠️ **It blocks; it cannot clean.** Claude Code has no mechanism for rewriting prompt text, only for
stopping it. So for anything you type, it's all-or-nothing. This is a platform limit, not a design
choice.

### Tool output — cleaned

When Claude reads a file or runs a command, the tool runs normally, then the plugin scans the
result **before the model sees it** and swaps secrets for labels:

```
lead:  swinalkm@gmail.com     →    lead:  [[EMAIL_1]]
dev:   bob@acme.io            →    dev:   [[EMAIL_2]]
port   5432                   →    port   5432          (untouched)
```

Claude still sees the structure and can still do the work — it just never sees the values.
Here the plugin **can** rewrite, unlike prompts.

### Writing to disk — asks first

If Claude is about to write a file containing protected data, you get a permission prompt naming
what was found. You decide — it asks rather than denying, because writing your own address into a
config file is a perfectly normal thing to do.

---

## Settings

`${CLAUDE_PLUGIN_DATA}/policy.json`, also update-safe:

| Setting | Values | Meaning |
|---|---|---|
| `mode` | `guard` | Block, clean, and ask. Default |
| | `detect` | Never block or modify — only log. Good for a trial week |
| | `off` | Fully inert |
| `audit` | `true` / `false` | Write the log |

## The audit log

`${CLAUDE_PLUGIN_DATA}/audit.jsonl` — one line per event:

```json
{"ts":"2026-09-23T10:04:21Z","v":"0.1.0","event":"UserPromptSubmit","tool":null,
 "action":"block","hits":[{"class":"EMAIL","id":"0a1cd0c7cbfb"}]}
```

`id` is `HMAC-SHA256(per-install random salt, value)`. **The secret is never written to disk**, and
a plain hash isn't used either — `sha256` of a phone number or date of birth can be brute-forced in
seconds. The HMAC lets you count distinct values without creating a crackable store of the very
things you're protecting.

## Privacy

Nothing is transmitted. No telemetry, no error reporting, no network calls. Your secrets file, the
salt, and the audit log stay on your machine. The author of this plugin receives nothing.

---

## Limitations — read this

Harm reduction for a common accident. **Not a security boundary.**

**Only Claude Code.** See [the table above](#where-this-works). Prompts typed into claude.ai are
completely unprotected.

**Prompts can only be blocked, not cleaned.** Platform limit.

**It cannot un-send.** Only the current turn is filtered. Anything already in your transcript stays
there, and transcript files on disk are not scrubbed.

**It matches formats, not meaning.** "My daughter goes to St Xaviers in Pune" is invisible to it.
Names, addresses, and contextual disclosure need a language model, not regex. Realistic recall on
free-form prose is roughly **60–70%**; on structured credentials it's much higher.

**Another plugin can silently defeat it.** Tool-output hooks run in parallel and the last write
wins. If you also run a hook that rewrites tool output — log compressors, output truncators — it
may overwrite this plugin's redaction with no warning.

**It assumes a cooperative user.** Not a defence against prompt injection, a malicious model, or
deliberate exfiltration.

**It is not a compliance control.** Not GDPR, PCI-DSS, HIPAA, SOC 2, or DLP. Don't represent it as
one.

**It does not scan commits.** Use [gitleaks](https://github.com/gitleaks/gitleaks) — different
problem, better solved elsewhere.

**Detection rates are unmeasured.** Per-class precision and recall will be published here once the
corpus harness runs. Until then, treat coverage as unproven.

---

## Development

```bash
git clone https://github.com/swinalkm/PIIGuardrail.git
cd PIIGuardrail
```

Install your working copy so edits are live — the marketplace points at the directory,
so changing `hooks/scan.py` takes effect on the next session with no reinstall:

```bash
claude plugin marketplace add "$PWD"
claude plugin install piiguard@piiguard
```

Exercise a hook directly, without installing anything:

```bash
export CLAUDE_PLUGIN_ROOT="$PWD"
export CLAUDE_PLUGIN_DATA=/tmp/pg-dev

echo '{"hook_event_name":"SessionStart"}' | ./hooks/run.sh
echo '{"hook_event_name":"UserPromptSubmit","prompt":"key AKIAIOSFODNN7EXAMPLE"}' | ./hooks/run.sh
```

Empty output means allowed; JSON with `"decision":"block"` means blocked.

**Design notes.** Fail open, loudly — an internal error exits cleanly and warns on stderr; a crash
must never break a session, and must never be mistaken for a deliberate block. Rewrites preserve
structure, since replacement tool output is schema-validated. Work is bounded: Python's `re` has no
timeout, so oversized inputs fall back to anchored patterns and the hook has a hard 5s limit.

Architecture: [docs/WORKFLOW.md](docs/WORKFLOW.md).

## Contributing

Detectors are declarative — a pattern, a validator, and corpus entries. Every new detector needs
test cases for what it must catch **and** what it must not. The bar for default-on is near-zero
false positives on real codebases; when in doubt, ship it off by default.

## License

MIT
