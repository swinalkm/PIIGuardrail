#!/usr/bin/env python3
"""PII Guardrail - scans Claude Code prompts and tool output for protected data.

Single file, stdlib only, invoked once per hook event by run.sh.

v0.2.0 implements 17 detectors. Adding a class is one row in DETECTORS plus one
line in default-secrets.txt - the surrounding machinery is already generic.

Design constraints (see docs/IMPLEMENTATION.md):
  - stdlib only. Claude Code cannot pip install at plugin install time.
  - single file. Startup is paid on every prompt and every tool call; measured
    budget is p95 < 25ms against a ~14ms interpreter floor.
  - fail open, loudly. An exception must never break a session, and must never
    be mistaken for a deliberate block.
  - structure-preserving rewrites. updatedToolOutput is validated against each
    tool's output schema, so only string leaves may ever change.
"""

import json
import os
import re
import sys

VERSION = "0.2.0"

# ---------------------------------------------------------------- limits ----
# Python's `re` has no timeout, so bound the work instead of trusting patterns.
MAX_INPUT_BYTES = 1_048_576   # above this, anchored patterns only
MAX_LINE_BYTES = 4096         # skip unanchored patterns on longer lines


# ------------------------------------------------------------ validators ----
# Each takes (match, cfg) and returns True to keep the match. This is where
# false positives die - a pattern alone is never enough.

def _allowlisted(text, cfg):
    low = text.lower()
    for entry in cfg.allow:
        if entry in low:
            return True
    return False


def _entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    import math
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


PLACEHOLDER_WORDS = (
    "changeme", "change-me", "placeholder", "example", "redacted", "todo",
    "yourkey", "your-key", "your_key", "insert", "dummy", "sample", "fake",
    "none", "null", "test", "secret", "password", "xxxx", "abc123",
)


def _looks_placeholder(v):
    low = v.lower().strip("\"'<>[]{}()")
    if not low:
        return True
    if len(set(low)) <= 2:            # xxxxxxx, 0000000, aaaa
        return True
    for w in PLACEHOLDER_WORDS:
        if w in low:
            return True
    return False


def _valid_email(m, cfg):
    return not _allowlisted(m.group(0), cfg)


def _valid_high_entropy(m, cfg):
    """For token formats whose body should look random."""
    v = m.group(1) if m.groups() else m.group(0)
    if _allowlisted(m.group(0), cfg) or _looks_placeholder(v):
        return False
    return _entropy(v) >= 3.0


def _valid_jwt(m, cfg):
    """A real JWT header base64-decodes to JSON containing alg."""
    if _allowlisted(m.group(0), cfg):
        return False
    import base64
    header = m.group(1)
    try:
        raw = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return False
    return isinstance(obj, dict) and "alg" in obj


def _valid_db_uri(m, cfg):
    if _allowlisted(m.group(0), cfg):
        return False
    return not _looks_placeholder(m.group(1))


def _luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# Luhn-valid numbers published by payment processors for testing. Redacting
# these breaks payment-integration work for no security benefit.
TEST_PANS = frozenset((
    "4111111111111111", "4012888888881881", "4222222222222",
    "4242424242424242", "4000056655665556", "5555555555554444",
    "5105105105105100", "5200828282828210", "378282246310005",
    "371449635398431", "6011111111111117", "6011000990139424",
    "3056930009020004", "30569309025904", "3566002020360505",
    "5431111111111111", "4000000000000002", "4917610000000000",
))

# Issuer prefixes we recognise. A Luhn-valid 16-digit number starting with 9 is
# far more likely to be an internal ID than a card.
_IIN = ("34", "37", "300", "301", "302", "303", "304", "305", "36", "38",
        "39", "4", "2221", "2720", "51", "52", "53", "54", "55", "6011",
        "622", "64", "65", "35")


def _valid_card(m, cfg):
    raw = m.group(0)
    if _allowlisted(raw, cfg):
        return False
    digits = raw.replace(" ", "").replace("-", "")
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    if digits in TEST_PANS:
        return False
    if not digits.startswith(_IIN):
        return False
    return _luhn_ok(digits)


_PRIVATE_IP = re.compile(
    r"^(?:0\.|10\.|127\.|169\.254\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|22[4-9]\.|2[3-5]\d\.|255\.)")


def _valid_public_ip(m, cfg):
    ip = m.group(0)
    if _allowlisted(ip, cfg):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or int(part) > 255:
            return False
        if len(part) > 1 and part[0] == "0":     # 01.2.3.4 is not an address
            return False
    return not _PRIVATE_IP.match(ip)


def _valid_phone(m, cfg):
    raw = m.group(0)
    if _allowlisted(raw, cfg):
        return False
    digits = "".join(c for c in raw if c.isdigit())
    if not 10 <= len(digits) <= 15:
        return False
    if "555010" in digits or "555011" in digits:   # reserved fictional range
        return False
    return len(set(digits)) > 3        # reject 1111111111, 1234567890


def _valid_dob(m, cfg):
    return not _allowlisted(m.group(0), cfg)


def _valid_plain(m, cfg):
    return not _allowlisted(m.group(0), cfg)


# ------------------------------------------------------------- detectors ----
# (name, pattern, validator, linear)
#
# `linear` means every quantifier is bounded or non-nested, so runtime grows
# linearly with input size and the pattern is safe on oversized input. Patterns
# marked False are skipped above MAX_INPUT_BYTES rather than risking a hang.
#
# To add a class: append a row here and document it in default-secrets.txt.
# PRIVATE_KEY is handled separately by _scan_pem - it spans lines.

DETECTORS = [
    # -- credentials -------------------------------------------------------
    ("AWS_ACCESS_KEY",
     re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"),
     _valid_plain, True),

    ("AWS_SECRET_KEY",
     re.compile(r"(?i)aws_?secret_?(?:access_?)?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"),
     _valid_high_entropy, True),

    ("GITHUB_TOKEN",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
     _valid_plain, True),

    ("ANTHROPIC_KEY",
     re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}"),
     _valid_plain, True),

    ("OPENAI_KEY",
     # (?!ant-) so an Anthropic key is not also claimed by this pattern; they
     # share the sk- prefix and would otherwise tie on span length.
     re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}"),
     _valid_plain, True),

    ("SLACK_TOKEN",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),
     _valid_plain, True),

    ("GOOGLE_API_KEY",
     re.compile(r"\bAIza[A-Za-z0-9_\-]{35}\b"),
     _valid_plain, True),

    ("STRIPE_KEY",
     re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
     _valid_plain, True),

    ("JWT",
     # group(1) must include the eyJ prefix - it is part of the base64 header,
     # and the validator decodes exactly what this group captures.
     re.compile(r"\b(eyJ[A-Za-z0-9_\-]{6,})\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{4,}"),
     _valid_jwt, True),

    ("DB_URI",
     re.compile(r"\b[a-z][a-z0-9+.\-]{2,15}://[^\s:/@]{1,64}:"
                r"([^\s:/@]{1,128})@[^\s/\"']{1,255}"),
     _valid_db_uri, True),

    ("GENERIC_SECRET",
     re.compile(r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|pwd|"
                r"auth|credential)\b\s*[:=]\s*[\"']?([A-Za-z0-9/+=_\-]{20,128})"),
     _valid_high_entropy, False),

    # -- personal data -----------------------------------------------------
    ("EMAIL",
     re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}\b"),
     _valid_email, True),

    ("CREDIT_CARD",
     re.compile(r"\b\d{13,19}\b|\b\d{4}(?:[ \-]\d{4}){2,4}\b"),
     _valid_card, True),

    ("PHONE",
     re.compile(r"(?:\+\d{1,3}[ \-]?)?(?:\(\d{2,4}\)[ \-]?)?\d{3,5}[ \-]?\d{3,4}[ \-]?\d{0,4}"),
     _valid_phone, True),

    ("IP_ADDRESS",
     re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     _valid_public_ip, True),

    ("DOB",
     re.compile(r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b"
                r"|\b(?:0[1-9]|[12]\d|3[01])[-/](?:0[1-9]|1[0-2])[-/](?:19|20)\d{2}\b"),
     _valid_dob, True),
]

DETECTOR_NAMES = set(d[0] for d in DETECTORS) | {"PRIVATE_KEY"}


# PEM blocks span lines, so a line walk is both safer and simpler than one
# large regex with a lazy quantifier over the body.
_PEM_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")


def _scan_pem(text):
    """Yield spans covering whole PEM private-key blocks."""
    spans = []
    pos = 0
    while True:
        b = _PEM_BEGIN.search(text, pos)
        if not b:
            return spans
        e = _PEM_END.search(text, b.end())
        if not e:
            return spans
        spans.append(Span(b.start(), e.end(), "PRIVATE_KEY",
                          text[b.start():e.end()]))
        pos = e.end()


def _redact_pem(block, label):
    """Replace a PEM body but keep the line count, so sibling metadata such as
    Read's numLines stays consistent."""
    lines = block.splitlines()
    if len(lines) < 3:
        return label
    return "\n".join([lines[0], label] + [""] * (len(lines) - 3) + [lines[-1]])


# ---------------------------------------------------------- secrets file ----

class Config(object):
    __slots__ = ("mode", "audit", "classes", "literals", "patterns",
                 "allow", "warnings")

    def __init__(self):
        self.mode = "guard"
        self.audit = True
        self.classes = set()
        self.literals = []
        self.patterns = []
        self.allow = []
        self.warnings = []


def _data_dir():
    """Where secrets.txt, policy.json, the salt and the audit log live.

    Claude Code exports CLAUDE_PLUGIN_DATA to hook processes, but NOT to a
    normal shell - so the --on/--off CLI has to resolve the same directory
    itself or it would write config the hook never reads.
    """
    d = os.environ.get("CLAUDE_PLUGIN_DATA")
    if d:
        return d
    standard = os.path.expanduser("~/.claude/plugins/data/piiguard-piiguard")
    if os.path.isdir(standard):
        return standard
    return os.path.expanduser("~/.piiguard")


def _plugin_root():
    return os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))


def parse_secrets(text, cfg):
    """Parse secrets.txt. Every failure degrades to a warning, never an error."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("!"):                       # !example.com -> allowlist
            entry = line[1:].strip().strip('"').lower()
            if entry:
                cfg.allow.append(entry)
            continue

        if len(line) > 2 and line.startswith("/") and line.endswith("/"):
            body = line[1:-1]
            try:
                cfg.patterns.append(re.compile(body))
            except re.error as exc:
                cfg.warnings.append("bad regex %s (%s)" % (line, exc))
            continue

        if len(line) > 1 and line[0] == line[-1] and line[0] in "\"'":
            entry = line[1:-1]
            if entry:
                cfg.literals.append(entry)
            continue

        name = line.upper()
        if name in DETECTOR_NAMES:
            cfg.classes.add(name)
        else:
            cfg.warnings.append("unknown entry %r - ignored" % line)
    return cfg


def load_config():
    cfg = Config()
    d = _data_dir()

    text = None
    for path in (os.path.join(d, "secrets.txt"),
                 os.path.join(_plugin_root(), "default-secrets.txt")):
        try:
            with open(path, "r") as fh:
                text = fh.read()
            break
        except Exception:
            continue
    if text:
        parse_secrets(text, cfg)

    try:
        with open(os.path.join(d, "policy.json"), "r") as fh:
            disk = json.load(fh)
        if disk.get("mode") in ("guard", "detect", "off"):
            cfg.mode = disk["mode"]
        if isinstance(disk.get("audit"), bool):
            cfg.audit = disk["audit"]
    except Exception:
        pass

    env_mode = os.environ.get("CLAUDE_PLUGIN_OPTION_MODE")
    if env_mode in ("guard", "detect", "off"):
        cfg.mode = env_mode
    env_audit = os.environ.get("CLAUDE_PLUGIN_OPTION_AUDIT")
    if env_audit is not None:
        cfg.audit = env_audit.lower() not in ("0", "false", "no")

    return cfg


# --------------------------------------------------------------- scanner ----

class Span(object):
    __slots__ = ("start", "end", "name", "text")

    def __init__(self, start, end, name, text):
        self.start = start
        self.end = end
        self.name = name
        self.text = text


def scan(text, cfg):
    """Return non-overlapping spans, longest match wins."""
    if not text:
        return []
    oversized = len(text) > MAX_INPUT_BYTES
    spans = []

    if "PRIVATE_KEY" in cfg.classes:
        spans.extend(_scan_pem(text))

    for name, pattern, validator, linear in DETECTORS:
        if name not in cfg.classes:
            continue
        if oversized and not linear:
            continue
        for m in pattern.finditer(text):
            if not linear and (m.end() - m.start()) > MAX_LINE_BYTES:
                continue
            if validator is not None and not validator(m, cfg):
                continue
            spans.append(Span(m.start(), m.end(), name, m.group(0)))

    for literal in cfg.literals:
        start = 0
        while True:
            i = text.find(literal, start)
            if i < 0:
                break
            spans.append(Span(i, i + len(literal), "LITERAL", literal))
            start = i + len(literal)

    # User regexes from secrets.txt are unvetted and could backtrack
    # catastrophically, so they are the one thing the size cap really guards.
    if not oversized:
        for pattern in cfg.patterns:
            for m in pattern.finditer(text):
                if m.end() > m.start():
                    spans.append(Span(m.start(), m.end(), "CUSTOM", m.group(0)))

    if not spans:
        return []

    spans.sort(key=lambda s: (s.start, -(s.end - s.start)))
    resolved, last_end = [], -1
    for s in spans:
        if s.start >= last_end:
            resolved.append(s)
            last_end = s.end
    return resolved


# --------------------------------------------------------------- redact ----

def redact(text, spans, counter):
    """Apply spans RIGHT TO LEFT so earlier offsets stay valid."""
    if not spans:
        return text, []
    # Number labels in READING order first, so the first match in the text is
    # _1. Substitution itself still runs right-to-left.
    labels = []
    for s in spans:
        counter[s.name] = counter.get(s.name, 0) + 1
        labels.append("[[%s_%d]]" % (s.name, counter[s.name]))

    out = text
    for s, label in zip(reversed(spans), reversed(labels)):
        body = _redact_pem(s.text, label) if s.name == "PRIVATE_KEY" else label
        out = out[:s.start] + body + out[s.end:]
    return out, [(s.name, s.text) for s in spans]


def deep_redact(obj, cfg, counter, found, depth=0):
    """Walk a tool_response, rewriting string leaves only.

    Keys and value types are preserved exactly, so the result still satisfies
    the tool's output schema. Returns (new_obj, changed).
    """
    if depth > 12:
        return obj, False
    if isinstance(obj, str):
        spans = scan(obj, cfg)
        if not spans:
            return obj, False
        new, hits = redact(obj, spans, counter)
        found.extend(hits)
        return new, new != obj
    if isinstance(obj, list):
        changed = False
        out = []
        for item in obj:
            new, ch = deep_redact(item, cfg, counter, found, depth + 1)
            out.append(new)
            changed = changed or ch
        return (out, True) if changed else (obj, False)
    if isinstance(obj, dict):
        changed = False
        out = {}
        for k, v in obj.items():
            new, ch = deep_redact(v, cfg, counter, found, depth + 1)
            out[k] = new
            changed = changed or ch
        if changed:
            _fix_line_counts(out)
            return out, True
        return obj, False
    return obj, False


def _fix_line_counts(node):
    """Keep Read's numLines consistent with rewritten content."""
    f = node.get("file")
    if isinstance(f, dict) and isinstance(f.get("content"), str):
        if isinstance(f.get("numLines"), int):
            f["numLines"] = f["content"].count("\n") + 1


# ---------------------------------------------------------------- audit ----

def _salt():
    """Per-install random salt, mode 0600.

    Plain sha256 of an email or phone number is brute-forceable, which would
    make this log a crackable store of the data it exists to protect.
    """
    import base64
    d = _data_dir()
    path = os.path.join(d, "salt")
    try:
        with open(path, "rb") as fh:
            s = fh.read().strip()
            if len(s) >= 16:
                return s
    except Exception:
        pass
    s = base64.b16encode(os.urandom(32))
    try:
        os.makedirs(d, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(s)
    except Exception:
        pass
    return s


def write_audit(event, tool, found, action, cfg):
    if not cfg.audit or not found:
        return
    try:
        import hashlib
        import hmac
        import time
        key = _salt()
        d = _data_dir()
        os.makedirs(d, exist_ok=True)
        line = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "v": VERSION,
            "event": event,
            "tool": tool,
            "action": action,
            "hits": [
                {"class": name,
                 "id": hmac.new(key, value.encode("utf-8", "replace"),
                                hashlib.sha256).hexdigest()[:12]}
                for name, value in found
            ],
        }
        with open(os.path.join(d, "audit.jsonl"), "a") as fh:
            fh.write(json.dumps(line) + "\n")
    except Exception:
        pass


# -------------------------------------------------------------- handlers ----

def handle_user_prompt_submit(payload, cfg):
    prompt = payload.get("prompt")
    if not isinstance(prompt, str):
        return None
    spans = scan(prompt, cfg)
    if not spans:
        return None

    found = [(s.name, s.text) for s in spans]
    write_audit("UserPromptSubmit", None, found, "block", cfg)
    if cfg.mode != "guard":
        return None

    classes = sorted(set(s.name for s in spans))
    # UserPromptSubmit cannot rewrite the prompt - block is the only option.
    return {
        "decision": "block",
        "reason": (
            "PII Guardrail blocked this message.\n"
            "Found: %s (%d occurrence(s)).\n"
            "Nothing was sent to Claude. Remove or replace the value and send "
            "again.\nTo stop flagging this, edit %s/secrets.txt."
            % (", ".join(classes), len(spans), _data_dir())),
    }


def handle_post_tool_use(payload, cfg):
    # The field is tool_response, NOT tool_output. Reading the wrong key finds
    # nothing and silently passes everything through.
    resp = payload.get("tool_response")
    if resp is None:
        return None

    counter, found = {}, []
    new, changed = deep_redact(resp, cfg, counter, found)
    if not found:
        return None

    write_audit("PostToolUse", payload.get("tool_name"), found,
                "redact" if (changed and cfg.mode == "guard") else "detect", cfg)

    classes = sorted(set(n for n, _ in found))
    out = {"hookEventName": "PostToolUse"}
    if cfg.mode == "guard" and changed:
        # Only ever emit a real rewrite. Hooks run in parallel last-write-wins,
        # so an identity rewrite could clobber another hook's redaction.
        out["updatedToolOutput"] = new
        out["additionalContext"] = (
            "PII Guardrail redacted %d value(s) (%s) from this tool output. "
            "Placeholders such as [[EMAIL_1]] stand in for real values. Do not "
            "try to reconstruct them or ask the user for them."
            % (len(found), ", ".join(classes)))
    else:
        out["additionalContext"] = (
            "PII Guardrail (detect mode): this output contains %d protected "
            "value(s) (%s). It was NOT redacted."
            % (len(found), ", ".join(classes)))
    return {"hookSpecificOutput": out}


WRITE_FIELDS = ("content", "new_string", "file_text")


def handle_pre_tool_use(payload, cfg):
    ti = payload.get("tool_input")
    if not isinstance(ti, dict):
        return None

    found = []
    for field in WRITE_FIELDS:
        val = ti.get(field)
        if isinstance(val, str):
            found.extend((s.name, s.text) for s in scan(val, cfg))
    if not found:
        return None

    write_audit("PreToolUse", payload.get("tool_name"), found, "ask", cfg)
    if cfg.mode != "guard":
        return None

    classes = sorted(set(n for n, _ in found))
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                "PII Guardrail: this write contains protected data (%s). "
                "Confirm you intend to put it on disk." % ", ".join(classes)),
        }
    }


def handle_session_start(_payload, cfg):
    """Seed state on first run. The only lifecycle point a plugin gets."""
    d = _data_dir()
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        return None

    target = os.path.join(d, "secrets.txt")
    if not os.path.exists(target):
        try:
            with open(os.path.join(_plugin_root(), "default-secrets.txt")) as fh:
                data = fh.read()
            with open(target, "w") as fh:
                fh.write(data)
        except Exception:
            pass

    policy = os.path.join(d, "policy.json")
    if not os.path.exists(policy):
        try:
            with open(policy, "w") as fh:
                json.dump({"mode": "guard", "audit": True}, fh, indent=2)
        except Exception:
            pass

    _salt()

    if cfg.warnings:
        sys.stderr.write("PII Guardrail: %s\n" % "; ".join(cfg.warnings[:5]))
    return None


HANDLERS = {
    "UserPromptSubmit": handle_user_prompt_submit,
    "PostToolUse": handle_post_tool_use,
    "PreToolUse": handle_pre_tool_use,
    "SessionStart": handle_session_start,
}


# ------------------------------------------------------------------ main ----

# ------------------------------------------------------------------ CLI ----
# Invoked as `scan.py --on|--off|--detect|--status` from a terminal or the
# /piiguard slash command. Hook events never pass these flags, and the check
# happens before stdin is read so the CLI does not block waiting for input.

_CLI_MODES = {"--on": "guard", "--off": "off", "--detect": "detect"}


def _set_mode(mode):
    d = _data_dir()
    path = os.path.join(d, "policy.json")
    try:
        with open(path) as fh:
            policy = json.load(fh)
    except Exception:
        policy = {"mode": "guard", "audit": True}
    policy["mode"] = mode
    try:
        os.makedirs(d, exist_ok=True)
        with open(path, "w") as fh:
            json.dump(policy, fh, indent=2)
    except Exception as exc:
        sys.stdout.write("Could not write %s: %s\n" % (path, exc))
        return 1
    return 0


def _status(cfg):
    labels = {"guard": "ON  (blocking and redacting)",
              "detect": "DETECT (logging only, nothing blocked)",
              "off": "OFF (inactive)"}
    lines = ["PII Guardrail v%s" % VERSION,
             "  status   : %s" % labels.get(cfg.mode, cfg.mode),
             "  detectors: %d %s" % (len(cfg.classes),
                                     "configured (not running)"
                                     if cfg.mode == "off" else "active"),
             "  config   : %s/secrets.txt" % _data_dir()]
    if cfg.classes and cfg.mode != "off":
        names = sorted(n.lower() for n in cfg.classes)
        lines.append("  watching : %s" % ", ".join(names))
    if cfg.allow:
        lines.append("  allowed  : %s" % ", ".join(cfg.allow))
    if cfg.warnings:
        lines.append("  warnings : %s" % "; ".join(cfg.warnings[:3]))
    audit_path = os.path.join(_data_dir(), "audit.jsonl")
    try:
        with open(audit_path) as fh:
            lines.append("  detections logged: %d" % sum(1 for _ in fh))
    except Exception:
        lines.append("  detections logged: 0")
    return "\n".join(lines)


def cli(argv):
    arg = argv[1]
    if arg in _CLI_MODES:
        mode = _CLI_MODES[arg]
        rc = _set_mode(mode)
        if rc == 0:
            sys.stdout.write(_status(load_config()) + "\n")
        return rc
    if arg == "--status":
        sys.stdout.write(_status(load_config()) + "\n")
        return 0
    sys.stdout.write(
        "PII Guardrail v%s\n\n"
        "  --on       enable (block and redact)\n"
        "  --off      disable entirely\n"
        "  --detect   log only, never block\n"
        "  --status   show current state\n" % VERSION)
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1].startswith("--"):
        return cli(sys.argv)

    raw = sys.stdin.read()
    if not raw.strip():
        return 0

    payload = json.loads(raw)
    event = payload.get("hook_event_name") or (
        sys.argv[1] if len(sys.argv) > 1 else "")
    handler = HANDLERS.get(event)
    if handler is None:
        return 0

    cfg = load_config()
    if cfg.mode == "off" and event != "SessionStart":
        return 0

    result = handler(payload, cfg)
    if result:
        sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    try:
        _rc = main()
    except SystemExit:
        # Our own clean exit. SystemExit derives from BaseException, so without
        # this it would be caught below and reported as a crash on every call.
        raise
    except BaseException as exc:  # noqa: BLE001 - fail open, always
        # NEVER exit 2 here. Exit 2 is the block signal, and a crash must not
        # read as a deliberate deny.
        try:
            sys.stderr.write(
                "PII Guardrail failed open (%s: %s). Your session is "
                "unaffected, but the filter did NOT run for this event.\n"
                % (type(exc).__name__, exc))
        except Exception:
            pass
        _rc = 0
    sys.exit(_rc)
