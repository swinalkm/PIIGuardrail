# PII Guardrail — Workflow & Architecture

Python. One shared detection core, two thin adapters. Regex + validators only.
Actions: **redact/tokenize** and **warn-and-log**. PII classes: global standard + secrets/credentials.

> Diagrams are Mermaid — they render natively on GitHub and in VS Code
> (Markdown Preview, or the *Markdown Preview Mermaid Support* extension).

---

## 1. System overview

Everything funnels through one scanner. The adapters only know how to find text and what to do with the result.

```mermaid
flowchart TB
    subgraph SRC["Text entering or leaving the system"]
        S1["User prompt<br/>Claude Code"]
        S2["Tool output<br/>Read / Grep / Bash"]
        S3["Tool input<br/>Bash / Write / Edit"]
        S4["App request<br/>system + messages"]
        S5["Model response<br/>buffered or streamed"]
    end

    subgraph ADPT["Adapters"]
        HOOK["adapters/hooks<br/>stdin JSON to stdout JSON"]
        MID["adapters/api<br/>GuardedAnthropic wrapper"]
    end

    subgraph CORE["piiguard.core — the only place detection logic lives"]
        REG["registry.py<br/>Detector protocol"]
        DET["detectors/<br/>regex + validator pairs"]
        RES["resolve.py<br/>overlap resolution"]
        POL["policy.py<br/>per-entity action + allowlists"]
        RDC["redact.py<br/>apply spans / restore"]
        VLT["vault.py<br/>placeholder to original<br/>in-memory, session-scoped"]
        AUD["audit.py<br/>JSONL, hashed only"]
    end

    FUT["Future detectors<br/>Presidio NER / Haiku classifier<br/>slot in at the protocol"]

    S1 --> HOOK
    S2 --> HOOK
    S3 --> HOOK
    S4 --> MID
    S5 --> MID

    HOOK --> REG
    MID --> REG
    REG --> DET
    DET --> RES
    RES --> POL
    POL --> RDC
    RDC <--> VLT
    POL --> AUD
    RDC --> AUD
    FUT -.implements.-> REG

    RDC --> OUT["Cleaned text<br/>back to the calling adapter"]
```

The `Detector` protocol is the seam. `scan(text) -> Iterable[Span]` is the whole contract, so a
Presidio or LLM pass can be added later without touching either adapter.

---

## 2. Detection pipeline

Two stages per class: a cheap regex finds candidates, a validator kills false positives.
The validator is what makes this usable — regex alone on credit cards and generic secrets is unbearably noisy.

```mermaid
flowchart TD
    IN["Raw text + source metadata"] --> FAN{"Fan out to all<br/>registered detectors"}

    FAN --> G1["Global classes"]
    FAN --> G2["Secrets / credentials"]

    subgraph GLOBAL["Global standard"]
        G1 --> E1["EMAIL — RFC-lite regex"] --> EV1["domain not in allowlist"]
        G1 --> E2["PHONE — E.164 + loose"] --> EV2["length + country prefix<br/>reject 555-01xx"]
        G1 --> E3["CREDIT_CARD — 13-19 digits"] --> EV3["Luhn + IIN range"]
        G1 --> E4["IP_ADDRESS — v4 / v6"] --> EV4["reject loopback, RFC1918, 0.0.0.0"]
        G1 --> E5["DOB — common date formats"] --> EV5["plausible year range"]
    end

    subgraph SECRETS["Secrets / credentials"]
        G2 --> K1["ANTHROPIC_KEY — sk-ant prefix"] --> KV1["length check"]
        G2 --> K2["AWS_ACCESS_KEY — AKIA + 16"] --> KV2["paired secret via Shannon entropy"]
        G2 --> K3["GITHUB_TOKEN — ghp/gho/ghu/ghs/ghr"] --> KV3["length check"]
        G2 --> K4["JWT — eyJ + two dots"] --> KV4["base64 header decodes to JSON"]
        G2 --> K5["PRIVATE_KEY — PEM BEGIN block"] --> KV5["matching END block"]
        G2 --> K6["DB_URI — scheme user pass host"] --> KV6["password group non-empty"]
        G2 --> K7["GENERIC_SECRET — key/token/password assign"] --> KV7["entropy >= 3.5<br/>reject xxx, changeme, your-key"]
    end

    EV1 --> SP["Candidate spans"]
    EV2 --> SP
    EV3 --> SP
    EV4 --> SP
    EV5 --> SP
    KV1 --> SP
    KV2 --> SP
    KV3 --> SP
    KV4 --> SP
    KV5 --> SP
    KV6 --> SP
    KV7 --> SP

    SP --> AL["Allowlist filter<br/>literals + patterns + own email"]
    AL --> OV["Overlap resolution<br/>longest match wins, then priority"]
    OV --> PL{"Policy lookup<br/>per entity class"}

    PL -->|redact| RD["Replace with placeholder<br/>record in vault"]
    PL -->|warn| WN["Leave text intact<br/>emit audit line"]
    PL -->|allow| PS["Pass through untouched"]

    RD --> AUDIT[("audit.jsonl")]
    WN --> AUDIT
    RD --> RET["ScanResult<br/>text + spans + vault handle"]
    WN --> RET
    PS --> RET
```

### Detector table

| Class | Pattern | Validator |
|---|---|---|
| `EMAIL` | RFC-lite | domain not in allowlist (`example.com`, `*.test`) |
| `PHONE` | E.164 + loose | length + country prefix; reject `555-01xx` |
| `CREDIT_CARD` | 13–19 digits, separators tolerated | **Luhn** + IIN range |
| `IP_ADDRESS` | IPv4 / IPv6 | reject loopback / RFC1918 / `0.0.0.0` by default (configurable) |
| `DOB` | common date formats | plausible year range |
| `ANTHROPIC_KEY` | `sk-ant-*` | prefix + length |
| `AWS_ACCESS_KEY` | `AKIA[0-9A-Z]{16}` | paired secret via Shannon entropy ≥ 3.5 |
| `GITHUB_TOKEN` | `gh[pousr]_[A-Za-z0-9]{36}` | — |
| `JWT` | `eyJ` + two dots | base64 header decodes to JSON |
| `PRIVATE_KEY` | `-----BEGIN .* PRIVATE KEY-----` | matching END block |
| `DB_URI` | `scheme://user:pass@host` | password group non-empty |
| `GENERIC_SECRET` | `(api[_-]?key\|secret\|token\|password)\s*[:=]\s*['"]?(\S{20,})` | entropy ≥ 3.5, not a known placeholder |

Street addresses and full names are **out of scope** with regex-only — see §8.

---

## 3. Policy and the restore gate

`action` and `restore` are separate axes. That separation is the point: you want the placeholder
swapped back for an email address, and you never want a live AWS key written back into a file.

```mermaid
flowchart LR
    SPAN["Resolved span<br/>entity = CREDIT_CARD"] --> LOOK{"policy.entities<br/>lookup"}
    LOOK -->|miss| DEF["default_action"]
    LOOK -->|hit| ACT{"action"}
    DEF --> ACT

    ACT -->|warn| W["text unchanged<br/>audit line written"]
    ACT -->|allow| A["text unchanged<br/>no audit line"]
    ACT -->|redact| R["substitute placeholder<br/>double-bracket TYPE_N"]

    R --> VQ{"restore flag"}
    VQ -->|true| V1["store original in vault<br/>outbound restore allowed"]
    VQ -->|false| V2["discard original<br/>placeholder is permanent"]

    V1 --> OUTB["On response: swap back"]
    V2 --> OUTB2["On response: leave as placeholder<br/>secret never re-enters the transcript"]
```

```yaml
# piiguard.yaml
default_action: warn          # Phase 3 starts here
entities:
  EMAIL:           {action: redact, restore: true}
  PHONE:           {action: redact, restore: true}
  CREDIT_CARD:     {action: redact, restore: false}
  DOB:             {action: redact, restore: true}
  IP_ADDRESS:      {action: warn}
  ANTHROPIC_KEY:   {action: redact, restore: false}
  AWS_ACCESS_KEY:  {action: redact, restore: false}
  GITHUB_TOKEN:    {action: redact, restore: false}
  JWT:             {action: redact, restore: false}
  PRIVATE_KEY:     {action: redact, restore: false}
  DB_URI:          {action: redact, restore: false}
  GENERIC_SECRET:  {action: redact, restore: false}
allowlist:
  literals:
    - "swinal@caizin.com"
    - "4111111111111111"
  patterns:
    - "example\\.com$"
```

**Placeholder format `[[EMAIL_1]]`** — low collision with real text, survives tokenization intact,
and numbering is stable within a session so the model can co-refer across turns
("email the first address").

---

## 4. Adapter A — Claude Code hooks

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant CC as Claude Code
    participant H as piiguard hook
    participant V as Vault + Audit
    participant API as Claude API

    U->>CC: types a prompt
    CC->>H: UserPromptSubmit, JSON on stdin
    H->>H: scan + redact prompt
    H->>V: store originals, write audit line
    H-->>CC: rewritten prompt on stdout
    CC->>API: request with placeholders only
    API-->>CC: assistant turn, wants a tool

    rect rgb(245, 235, 220)
    note over CC,H: Outbound guard
    CC->>H: PreToolUse for Bash / Write / Edit
    H->>H: scan tool_input for secrets
    alt secret found and action is redact
        H-->>CC: rewritten tool_input
    else warn only
        H->>V: audit line
        H-->>CC: unchanged, allow
    end
    end

    CC->>CC: run the tool

    rect rgb(225, 240, 235)
    note over CC,H: Inbound guard — highest value
    CC->>H: PostToolUse for Read / Grep / Bash
    H->>H: scan tool output
    note right of H: a single cat .env would<br/>dump the whole credential set<br/>into context
    H->>V: audit line
    H-->>CC: redacted tool output
    end

    CC->>API: tool_result with placeholders
    API-->>CC: final answer
    CC-->>U: answer
```

| Hook | Surface guarded | Why |
|---|---|---|
| `UserPromptSubmit` | the prompt | catches PII before it leaves the machine |
| `PreToolUse` | `Bash`, `Write`, `Edit` inputs | catches secrets heading outbound into a command or file |
| `PostToolUse` | `Read`, `Grep`, `Bash` output | **highest value** — stops file/command output from poisoning context |

### Two things to handle here

```mermaid
flowchart LR
    subgraph RISK1["Risk: hook JSON contract"]
        A1["Confirm current stdin/stdout schema<br/>against live docs"] --> A2["hookSpecificOutput shape,<br/>exit-code semantics,<br/>can UserPromptSubmit rewrite or only block"]
        A2 --> A3["Then write the adapter"]
    end

    subgraph RISK2["Risk: latency"]
        B1["Hooks fire on every prompt<br/>and every tool call"] --> B2["Python cold start 80-150ms"]
        B2 --> B3["Module-level precompiled regex<br/>+ lazy imports"]
        B3 --> B4{"p95 under 50ms?"}
        B4 -->|yes| B5["Ship it"]
        B4 -->|no| B6["Persistent daemon over<br/>unix socket + thin client"]
    end
```

Verify the hook schema **before** writing the adapter rather than working from memory — this API has moved.
The latency budget is **p95 < 50 ms**, measured, not assumed.

---

## 5. Adapter B — API middleware

`GuardedAnthropic` mirrors the SDK surface so it drops in for `client.messages.create` / `.stream`.
Default model `claude-opus-5`.

```mermaid
flowchart TB
    APP["Your app"] --> GC["GuardedAnthropic.messages.create / .stream"]

    subgraph INB["Inbound"]
        GC --> W["Walk every text-bearing field"]
        W --> W1["system"]
        W --> W2["messages[].content text blocks"]
        W --> W3["tool_result blocks"]
        W --> W4["document titles"]
        W1 --> SC["core.scan + redact"]
        W2 --> SC
        W3 --> SC
        W4 --> SC
        SC --> VH["Vault retained<br/>for this request"]
    end

    SC --> SDK["anthropic SDK<br/>messages.create / messages.stream"]
    SDK --> ANT["Claude API"]
    ANT --> RESP{"streaming?"}

    RESP -->|no| NB["Buffered path"]
    RESP -->|yes| ST["Streaming path"]

    subgraph OUTB["Outbound — buffered"]
        NB --> NB1["restore placeholders where restore = true"]
        NB1 --> NB2["re-scan output for PII<br/>NOT present in the input"]
        NB2 --> NB3["leak detection audit line"]
    end

    subgraph OUTS["Outbound — streamed"]
        ST --> ST1["tail-window buffer<br/>state machine"]
        ST1 --> ST2["get_final_message for<br/>the completed turn"]
        ST2 --> NB2
    end

    NB3 --> APP2["Clean response to app"]
```

Leak detection is free once the scanner exists: anything PII-shaped in the output that was
**not** in the input means the model produced it, and that is worth a log line.

### The streaming state machine

The one genuinely tricky piece. A placeholder can split across chunks — `[[EMA` then `IL_1]]` —
so naive per-chunk restore silently corrupts output. This is the **#1 bug** in systems like this,
and it gets its own test suite.

```mermaid
stateDiagram-v2
    [*] --> Passthrough

    Passthrough: Passthrough
    Passthrough: yield chunks straight through
    Buffering: Buffering
    Buffering: hold a tail window of max placeholder length
    Resolve: Resolve
    Resolve: complete placeholder recognised

    Passthrough --> Buffering: sees a candidate opening delimiter
    Buffering --> Buffering: still partial, keep holding
    Buffering --> Passthrough: cannot become a placeholder, flush held text verbatim
    Buffering --> Resolve: full placeholder token assembled
    Resolve --> Passthrough: restore = true, emit original
    Resolve --> Passthrough: restore = false, emit placeholder unchanged
    Passthrough --> [*]: stream ends, flush remaining tail
    Buffering --> [*]: stream ends mid-token, flush held text verbatim
```

Built on `client.messages.stream()` + `get_final_message()` — no hand-rolled event plumbing.

---

## 6. Data model, vault and audit

```mermaid
classDiagram
    class Span {
        +int start
        +int end
        +str entity_type
        +str text
        +float confidence
        +str detector
    }
    class ScanResult {
        +str text
        +list~Span~ spans
        +VaultHandle vault
        +bool modified
    }
    class Detector {
        <<protocol>>
        +str entity_type
        +int priority
        +scan(text) Iterable~Span~
    }
    class Vault {
        -dict placeholder_to_original
        +str session_id
        +mint(span) str
        +restore(text) str
        +clear() None
    }
    class Policy {
        +Action default_action
        +dict entities
        +Allowlist allowlist
        +resolve(entity_type) EntityPolicy
    }
    class AuditRecord {
        +str ts
        +str surface
        +str entity_type
        +str detector
        +int offset
        +str sha12
        +str action
        +str session_id
    }

    Detector ..> Span : produces
    ScanResult o-- Span
    ScanResult o-- Vault
    Policy ..> AuditRecord : decides action for
    Vault ..> AuditRecord : never stores plaintext in
```

### The audit rule

```mermaid
flowchart LR
    ORIG["Original value<br/>4111 1111 1111 1111"] --> HASH["sha256 then take 12 chars"]
    HASH --> LINE["audit.jsonl line<br/>sha12 = a94a8fe5ccb1"]
    ORIG -.->|NEVER| LINE

    LINE --> USE1["Count detections per class"]
    LINE --> USE2["Count DISTINCT values<br/>hash prefix is enough"]
    LINE --> USE3["Decide Phase 5 flips"]
```

Plaintext never reaches the log. Otherwise your PII guardrail becomes your largest PII store.
The hash prefix still lets you count distinct values during the warn-only soak.

---

## 7. Testing strategy

```mermaid
flowchart TB
    subgraph T1["Golden corpus"]
        C1["tests/corpus/*.txt<br/>inline expectations<br/>EXPECT EMAIL at 10-25"] --> C2["P/R harness"]
        C2 --> C3["precision + recall<br/>reported per entity class"]
        C3 --> C4["Gate: no warn to redact flip<br/>without measured numbers"]
    end

    subgraph T2["Adversarial set"]
        A1["PII split across lines"] --> A2["Run scanner"]
        A3["spaced-out digits"] --> A2
        A4["base64 encoded"] --> A2
        A5["homoglyphs"] --> A2
        A2 --> A6["Document the miss rate<br/>goal is honesty, not zero"]
    end

    subgraph T3["Property tests"]
        P1["restore(redact(x)) == x"] --> P4["hypothesis"]
        P2["never crashes on any input"] --> P4
        P3["never drops or reorders<br/>non-PII text"] --> P4
    end

    subgraph T4["Streaming tests"]
        S1["chunk boundary at every byte<br/>of every placeholder"] --> S2["output identical to<br/>buffered path"]
    end
```

---

## 8. Phasing

```mermaid
gantt
    title Build order — Phase 3 soak is the part worth protecting
    dateFormat YYYY-MM-DD
    axisFormat %b %d

    section Core
    Phase 0  Scaffold, types, policy loader, audit sink   :p0, 2026-09-17, 1d
    Phase 1  Detectors, validators, allowlists, corpus    :p1, after p0, 2d
    Phase 2  Redaction engine, vault, roundtrip props     :p2, after p1, 1d

    section Adapters
    Phase 3  Hooks adapter, deployed warn-only            :p3, after p2, 1d
    Phase 3  Soak week, read the audit log               :crit, p3s, after p3, 7d
    Phase 4  API middleware + streaming state machine     :p4, after p3, 2d

    section Rollout
    Phase 5  Flip per-entity to redact on measured data   :p5, after p3s, 1d
```

| Phase | Work | Est. |
|---|---|---|
| 0 | Scaffold, `pyproject`, core types, policy loader, audit sink | 0.5 d |
| 1 | Detectors + validators + allowlists + corpus, **with measured P/R** | 2 d |
| 2 | Redaction engine + vault + roundtrip properties | 1 d |
| 3 | Hooks adapter, deployed **warn-only** | 1 d + 1 wk soak |
| 4 | API middleware incl. streaming state machine | 2 d |
| 5 | Read the soak audit log, flip per-entity to `redact` where earned | 0.5 d |

Turning on redaction before you've seen real hit rates is how you end up with a guardrail
everyone disables. Phase 3's soak week is what prevents that.

```mermaid
flowchart LR
    W["All entities: warn<br/>1 week soak"] --> READ["Read audit.jsonl"]
    READ --> Q{"Per entity class"}
    Q -->|"high hit rate,<br/>low false positives"| F1["flip to redact"]
    Q -->|"noisy"| F2["tighten validator<br/>or extend allowlist"]
    Q -->|"never fires"| F3["leave at warn<br/>or drop the detector"]
    F2 --> W
```

---

## 9. Known limits — stated up front

```mermaid
flowchart TB
    subgraph IN_SCOPE["Caught well — high 90s recall"]
        I1["Credit cards"]
        I2["API keys and tokens"]
        I3["Email addresses"]
        I4["Private key blocks"]
        I5["Connection strings"]
    end

    subgraph OUT_SCOPE["Not caught — regex cannot do this"]
        O1["Full names"]
        O2["Street addresses"]
        O3["Contextual disclosure<br/>my daughter goes to<br/>St Xaviers school in Pune"]
    end

    subgraph LATER["Buy the remaining recall later"]
        L1["Presidio + spaCy NER"]
        L2["Haiku classifier pass"]
    end

    OUT_SCOPE -.->|"when the dependency<br/>is worth it"| LATER
    LATER -.->|"implements Detector protocol,<br/>adapters unchanged"| DONE["No rewrite needed"]
```

Realistic recall on free-form prose is **60–70%**. This is a meaningful reduction in accidental
leakage, **not a compliance control**, and it should not be described as one internally.
