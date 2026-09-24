# PII Guardrail — Architecture

A Claude Code plugin. Scans prompts before they are sent, cleans tool output before the model sees
it, and asks before a credential is written to disk. Stdlib-only Python, driven by one user-editable
secrets file.

> Diagrams are Mermaid — they render on GitHub and in VS Code Markdown Preview.

---

## 1. Scope — what this can and cannot reach

The single most important constraint. A Claude Code plugin runs **locally, inside Claude Code**.
It cannot reach any other Anthropic surface.

```mermaid
flowchart TB
    subgraph COVERED["Protected by this plugin"]
        C1["Claude Code — terminal"]
        C2["Claude Code — VS Code / JetBrains"]
        C3["Subagents and background tasks"]
    end

    subgraph UNCOVERED["NOT protected — no local interception point"]
        U1["claude.ai web UI"]
        U2["Claude Desktop / mobile"]
        U3["Anthropic API / your own agents"]
    end

    C1 --> HOOK["Plugin hooks run on your machine<br/>before anything is sent"]
    C2 --> HOOK
    C3 --> HOOK
    HOOK --> API["Anthropic API"]

    U1 -->|"browser sends directly<br/>nothing local in between"| API
    U2 -->|"no plugin mechanism exists"| API
    U3 -->|"your code calls the API directly"| API
```

**Scope is deliberately one surface.** Covering the rest would mean separate products — a browser
extension for claude.ai, a proxy for the API — and they are not planned. Desktop and mobile have no
interception point at all short of network-level TLS inspection.

The detector layer is still kept free of Claude Code specifics, but for testability rather than
future reuse: pure functions with no hook payloads in them are far easier to run against a corpus.

---

## 2. System overview

```mermaid
flowchart TB
    SF[("secrets.txt<br/>user-editable<br/>survives updates")]

    subgraph EVENTS["Three interception points"]
        E1["UserPromptSubmit<br/>your prompt"]
        E2["PostToolUse<br/>tool output"]
        E3["PreToolUse<br/>file writes"]
    end

    subgraph ENTRY["Entry"]
        RUN["run.sh<br/>probes for python3"]
        CLI["cli.py<br/>dispatch + fail-open"]
    end

    subgraph CORE["Detection core — reusable, no Claude Code specifics"]
        POL["policy.py<br/>parses secrets.txt"]
        DET["detectors.py<br/>pattern + validator table"]
        VAL["validators.py<br/>kills false positives"]
        SCN["scanner.py<br/>size and line caps"]
        RES["resolve.py<br/>overlap resolution"]
    end

    subgraph ACT["Action"]
        RDC["redact.py<br/>substitute placeholders"]
        WLK["walk.py<br/>structure-preserving rewrite"]
        AUD["audit.py<br/>HMAC log"]
    end

    E1 --> RUN
    E2 --> RUN
    E3 --> RUN
    RUN --> CLI
    CLI --> POL
    SF --> POL
    POL --> SCN
    DET --> SCN
    VAL --> DET
    SCN --> RES
    RES --> RDC
    RDC --> WLK
    RES --> AUD
    WLK --> OUT["JSON verdict to Claude Code"]
```

---

## 3. The secrets file

One file is the whole configuration surface. Parsed on every invocation, so edits take effect on
the next prompt with no restart.

```mermaid
flowchart LR
    F["secrets.txt"] --> P{"line type"}
    P -->|"bare word<br/>aws_key"| C["enable a built-in detector"]
    P -->|"quoted<br/>&quot;acme-internal.corp&quot;"| L["literal string match"]
    P -->|"slashes<br/>/EMP-digits/"| R["user regex"]
    P -->|"# comment"| S["skipped"]

    C --> SET["active detector set"]
    L --> SET
    R --> SET
    SET --> SCAN["scanner"]
```

Shipped defaults enable credential classes only. Personal-data classes (`email`, `phone`,
`ip_address`, `dob`) are present but commented out — in a coding context they fire constantly on
`git log`, `CODEOWNERS`, `127.0.0.1`, and dates in changelogs. Uncommenting is a deliberate act.

---

## 4. Flow A — your prompt (block only)

```mermaid
sequenceDiagram
    autonumber
    actor U as You
    participant CC as Claude Code
    participant H as piiguard
    participant A as Anthropic API

    U->>CC: submit prompt
    CC->>H: UserPromptSubmit + prompt text
    H->>H: scan against secrets.txt

    alt nothing found
        H-->>CC: exit 0, silent
        CC->>A: prompt sent unchanged
        A-->>U: answer
    else match found
        H->>H: write HMAC audit line
        H-->>CC: decision block + reason
        CC-->>U: blocked, shows what matched
        note over U: nothing was sent<br/>edit and resend
    end
```

**The hook cannot clean a prompt.** Claude Code exposes no field for rewriting prompt text — only
for blocking it. Verified directly against the application. So for typed input this is necessarily
all-or-nothing.

---

## 5. Flow B — tool output (cleaned)

Where redaction genuinely works. The tool runs normally; only what reaches the model is altered.

```mermaid
sequenceDiagram
    autonumber
    participant CC as Claude Code
    participant T as Tool
    participant H as piiguard
    participant M as Model

    CC->>T: Read .env
    T-->>CC: tool_response with real values
    CC->>H: PostToolUse + tool_response
    H->>H: deep walk, scan string leaves

    alt no secrets
        H-->>CC: exit 0, silent
        CC->>M: original output
    else secrets found
        H->>H: clone structure, substitute values
        H->>H: HMAC audit line
        H-->>CC: updatedToolOutput + additionalContext
        CC->>CC: validate against tool output schema
        CC->>M: cleaned output
        note over M: sees AWS_ACCESS_KEY_ID<br/>but not its value
    end
```

Two details that decide whether this works at all:

- The stdin field is **`tool_response`**, not `tool_output`. Reading the wrong key finds nothing and
  silently passes every secret through — a failure indistinguishable from "clean".
- The replacement is **schema-validated per tool**. Only string leaves may change; keys and types
  must survive, or the rewrite is discarded and the original output is used.

---

## 6. Flow C — writes to disk (ask)

```mermaid
flowchart LR
    W["Claude wants to<br/>Write or Edit"] --> S["scan content"]
    S -->|clean| A["proceed"]
    S -->|credential found| ASK["permissionDecision: ask<br/>names the class"]
    ASK --> U{"your call"}
    U -->|approve| A
    U -->|reject| N["not written"]
```

`ask`, never `deny`. A denial is unappealable inside the turn — the model re-plans around it, often
worse, and you cannot consent without editing config. Writing a real key into `.env` is a
legitimate act.

---

## 7. Detection pipeline

Two stages per class: a cheap anchored regex finds candidates, a validator kills false positives.
The validator is what makes this usable rather than infuriating.

```mermaid
flowchart TD
    IN["text"] --> CAP{"size caps"}
    CAP -->|"over 1 MB"| ANCH["anchored patterns only"]
    CAP -->|normal| ALL["all enabled patterns"]
    ANCH --> M["candidate matches"]
    ALL --> M

    M --> V{"validator"}
    V -->|"CREDIT_CARD"| V1["Luhn + card prefix<br/>minus known test numbers"]
    V -->|"JWT"| V2["header base64-decodes to JSON"]
    V -->|"DB_URI"| V3["password real, not a placeholder"]
    V -->|"AWS secret"| V4["Shannon entropy >= 3.5"]
    V -->|"IP_ADDRESS"| V5["public only, skip loopback and RFC1918"]
    V -->|"EMAIL"| V6["domain not example.com or .test"]

    V1 --> K{"passed?"}
    V2 --> K
    V3 --> K
    V4 --> K
    V5 --> K
    V6 --> K
    K -->|no| DROP["discarded"]
    K -->|yes| SP["span kept"]

    SP --> OV["overlap resolution<br/>longest match wins"]
    OV --> ACT["action by event"]
```

Worked example — scanning `postgres://admin:hunter2@db.prod:5432/app`:

| Candidate | Detector | Verdict |
|---|---|---|
| `postgres://admin:hunter2@…` | `DB_URI` | password real → **keep** |
| `5432` | `CREDIT_CARD` | too short → **discard** |

Without the validator, that port number becomes a false positive on every connection string in the
codebase.

### ReDoS bounds

Python's `re` has **no timeout**, so a pathological input would hang for the whole hook timeout.

| Guard | Value |
|---|---|
| Hook timeout | 5 s — not the 600 s default, which would freeze a session for ten minutes |
| Input cap | 1 MB, above which only anchored patterns run |
| Line cap | 4 KB — minified bundles and base64 blobs are where backtracking lives |

---

## 8. Redaction mechanics

```mermaid
flowchart TB
    R["tool_response object"] --> W["deep walk"]
    W --> T{"leaf type"}
    T -->|string| SC["scan and substitute"]
    T -->|"int, bool, null"| KEEP["untouched"]
    T -->|"dict, list"| REC["recurse"]
    REC --> T

    SC --> ORD["apply spans right to left"]
    ORD --> WHY["so earlier offsets stay valid"]
    ORD --> FIX["recompute numLines if content changed"]
    FIX --> CH{"bytes actually changed?"}
    CH -->|yes| EMIT["emit updatedToolOutput"]
    CH -->|no| SKIP["emit nothing"]
```

**Never emit an unchanged rewrite.** Tool-output hooks run in parallel and the last write wins, so
returning an identity copy can clobber another plugin's real redaction.

Multi-line PEM blocks preserve their line count — the body is replaced with one placeholder line
plus blanks — so sibling metadata fields stay consistent.

---

## 9. Audit log

```mermaid
flowchart LR
    V["AKIAIOSFODNN7EXAMPLE"] --> H["HMAC-SHA256<br/>key = per-install random salt"]
    H --> ID["id = 9f2ac41b7e05"]
    V -.->|NEVER written| LOG[("audit.jsonl")]
    ID --> LOG
    LOG --> U1["count events per class"]
    LOG --> U2["count distinct values"]
```

Plain `sha256(value)[:12]` would be **brute-forceable** for exactly the classes that matter — a DOB
space is about 4×10⁴, a Luhn-valid card space about 10¹⁵. That would make the guardrail's own log a
crackable store of the data it exists to protect. HMAC with a local secret keeps distinct-value
counting and kills the dictionary attack.

Only acted-on events are logged; a log full of `127.0.0.1` trains you to ignore it.

---

## 10. Failure behaviour

```mermaid
flowchart TD
    S["hook invoked"] --> P{"python3 present?"}
    P -->|no| Q["exit 0 silently<br/>warn once per install"]
    P -->|yes| R["run scanner"]
    R --> E{"exception?"}
    E -->|no| N["normal verdict"]
    E -->|yes| F["exit 0, empty stdout<br/>loud stderr warning"]

    F --> W["NEVER exit 2 on an internal error"]
    W --> X["exit 2 means block —<br/>a crash must not read as a deliberate deny"]
```

**Fail open, loudly.** The threat model is an accidental leak by a cooperative user; fail-closed
only helps against an adversary who could simply not install the plugin. The blast radius is
asymmetric — failing open leaks one secret into a transcript you already own, failing closed kills
every tool call in the session. But a *silent* failure is worse than either, because it manufactures
false confidence.

---

## 11. Testing

```mermaid
flowchart TB
    subgraph CORP["Golden corpus"]
        A1["files with inline EXPECT markers"] --> A2["precision + recall per class"]
        A2 --> A3["gate: no class ships default-on<br/>without measured numbers"]
    end
    subgraph SHAPE["Shape tests"]
        B1["recorded tool_response fixtures"] --> B2["rewrite survives schema validation"]
    end
    subgraph ADV["Adversarial"]
        C1["split lines, spaced digits,<br/>base64, homoglyphs"] --> C2["document the miss rate"]
    end
    subgraph PROP["Properties"]
        D1["never crashes"] --> D3["hypothesis-style"]
        D2["never drops non-secret text"] --> D3
    end
    subgraph PERF["Performance"]
        E1["1 MB adversarial input"] --> E2["completes inside the bound"]
        E3["100 invocations"] --> E4["p95 under 25 ms"]
    end
```

Every handler is a pure function of its payload, so the entire hook surface is testable from
recorded JSON with no Claude Code running.

---

## 12. Build order

```mermaid
gantt
    title Phase 0 first — it can invalidate later phases
    dateFormat YYYY-MM-DD
    axisFormat %b %d
    section Verify
    Phase 0  Canary probe + fixtures        :crit, p0, 2026-09-24, 1d
    section Core
    Phase 1  Detectors + validators + corpus :p1, after p0, 2d
    Phase 2  Secrets file, policy, audit     :p2, after p1, 1d
    section Surface
    Phase 3  Three handlers                  :p3, after p2, 2d
    Phase 4  Robustness + perf               :p4, after p3, 1d
    Phase 5  Docs + release                  :p5, after p4, 1d
```

Phase 0 confirms, against a live session, that the tool-output rewrite actually reaches the model
and in which shape per tool. The oracle is the session transcript JSONL, not asking the model what
it saw.

---

## 13. Known limits

```mermaid
flowchart TB
    subgraph GOOD["Caught reliably"]
        G1["API keys and tokens"]
        G2["Private key blocks"]
        G3["Connection strings"]
        G4["Credit cards"]
    end
    subgraph BAD["Not caught — regex matches format, not meaning"]
        B1["Full names"]
        B2["Street addresses"]
        B3["Contextual disclosure"]
    end
    subgraph STRUCT["Structural limits"]
        S1["claude.ai and the API are unreachable"]
        S2["prompts can be blocked, not cleaned"]
        S3["cannot un-send earlier turns"]
        S4["a competing rewrite hook can win<br/>last-write-wins and re-expose"]
    end
```

Realistic recall on free-form prose is **60–70%**; on structured credentials, much higher. This is
harm reduction for a common accident, **not a compliance control**.
