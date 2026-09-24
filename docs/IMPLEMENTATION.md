# PII Guardrail — Implementation

Build-level detail: module graph, call paths, data structures, file lifecycle, test coverage, and
the order to build in. For *what the product does*, see [WORKFLOW.md](WORKFLOW.md). For *how to use
it*, see the [README](../README.md).

> Diagrams are Mermaid — they render on GitHub and in VS Code Markdown Preview.

---

## 1. Build sequence and decision gates

Two gates can change the design. Neither is skippable.

```mermaid
flowchart TB
    S0["Step 0 — CANARY SPIKE"]:::gate
    S0 --> G1{"does updatedToolOutput<br/>reach the model?"}
    G1 -->|no| STOP["STOP — product is detect-only<br/>reconsider whether to build"]:::bad
    G1 -->|yes| G2{"does pycache persist<br/>in the plugin dir?"}
    G2 -->|yes| PKG["package layout<br/>12 modules"]
    G2 -->|no| FLAT["single-file layout<br/>sections, not modules"]

    PKG --> S1
    FLAT --> S1
    S1["Step 1 — installable skeleton<br/>manifests, run.sh, no-op scan"]

    S1 --> S2["Step 2 — validators.py"]
    S2 --> S3["Step 3 — detectors.py"]
    S3 --> S4["Step 4 — secrets.py"]
    S4 --> S5["Step 5 — scanner.py + resolve.py"]
    S5 --> S6["Step 6 — redact.py + walk.py"]
    S6 --> S7["Step 7 — handlers"]
    S7 --> S8["Step 8 — audit.py"]
    S8 --> S9["Step 9 — fail-open + perf"]
    S9 --> S10["Step 10 — MEASURE"]:::gate
    S10 --> G3{"precision and recall<br/>good enough?"}
    G3 -->|no| S3
    G3 -->|yes| S11["Step 11 — release"]:::good

    classDef gate fill:#4a3f2a,stroke:#c9a227,color:#f0e6d2
    classDef bad fill:#4a2a2a,stroke:#c94227,color:#f0d2d2
    classDef good fill:#2a4a33,stroke:#27c96b,color:#d2f0dd
```

**Gate 1** decides whether the product exists. If tool-output rewriting does not work, this becomes
a detect-and-alert tool — strictly worse, and `gitleaks` already covers commit-time scanning better.

**Gate 2** decides file layout. `python3 -S -E` starts in ~8 ms; twelve modules with a warm
`__pycache__` add ~2 ms, but with a read-only plugin directory they re-compile every invocation and
add ~10–20 ms, against a 25 ms budget.

**Gate 3** is the honesty gate. No class ships enabled-by-default without measured numbers.

---

## 2. Module dependency graph

Strictly layered. Arrows point the way imports go; nothing points back up.

```mermaid
flowchart TB
    subgraph L5["Entry"]
        RUN["run.sh<br/>POSIX, probes python3"]
        CLI["cli.py<br/>stdin, dispatch, fail-open"]
    end

    subgraph L4["Handlers — one per hook event"]
        H1["user_prompt_submit.py"]
        H2["post_tool_use.py"]
        H3["pre_tool_use.py"]
        H4["session_start.py"]
    end

    subgraph L3["Action"]
        WLK["walk.py<br/>structure-preserving recursion"]
        RDC["redact.py<br/>span substitution"]
        AUD["audit.py<br/>HMAC + JSONL"]
    end

    subgraph L2["Detection"]
        SCN["scanner.py<br/>caps, orchestration"]
        RES["resolve.py<br/>overlap resolution"]
        DET["detectors.py<br/>pattern table"]
    end

    subgraph L1["Foundation — pure, no I/O"]
        VAL["validators.py"]
        SEC["secrets.py<br/>config parser"]
        TYP["types.py<br/>Span, Tier, Action"]
    end

    RUN --> CLI
    CLI --> H1
    CLI --> H2
    CLI --> H3
    CLI --> H4

    H1 --> SCN
    H1 --> AUD
    H2 --> WLK
    H2 --> AUD
    H3 --> SCN
    H3 --> AUD
    H4 --> SEC

    WLK --> SCN
    WLK --> RDC
    RDC --> TYP
    SCN --> RES
    SCN --> DET
    SCN --> SEC
    RES --> TYP
    DET --> VAL
    DET --> TYP
    SEC --> DET
```

Consequences of the layering:

- **L1 has no imports and no I/O.** Exhaustively unit-testable, and the layer where correctness
  actually lives.
- **Handlers are pure functions** of their payload — the whole hook surface is testable from
  recorded JSON with no Claude Code running.
- **Only `walk.py` and `redact.py` mutate text.** Everything else observes.

---

## 3. File tree

```
PIIGuardrail/
├── .claude-plugin/
│   ├── plugin.json              manifest, userConfig schema
│   └── marketplace.json         "source": "." — self-installing
├── hooks/
│   ├── hooks.json               4 events, matchers, timeout 5
│   ├── run.sh                   python3 probe then exec
│   └── scan.py                  entry; imports the package OR is the whole thing
├── piiguard/                    (omitted if Gate 2 says single-file)
│   ├── types.py                 Span, Tier, Action, ScanResult
│   ├── validators.py            luhn, entropy, jwt, placeholder, ip, card, email
│   ├── detectors.py             declarative pattern table
│   ├── secrets.py               secrets.txt parser
│   ├── scanner.py               caps + orchestration
│   ├── resolve.py               longest-match-wins
│   ├── redact.py                span substitution, PEM handling
│   ├── walk.py                  deep structure-preserving rewrite
│   ├── audit.py                 salt lifecycle, HMAC, JSONL
│   ├── cli.py                   dispatch + fail-open wrapper
│   └── handlers/
│       ├── user_prompt_submit.py
│       ├── post_tool_use.py
│       ├── pre_tool_use.py
│       └── session_start.py
├── default-secrets.txt          seeded to CLAUDE_PLUGIN_DATA on first run
├── default-policy.json          mode + audit defaults
├── tools/
│   ├── canary.py                Step 0 probe
│   ├── corpus_check.py          precision and recall reporter
│   └── bench.py                 p95 latency assertion
├── tests/
│   ├── fixtures/                REAL payloads captured in Step 0
│   ├── corpus/                  golden files with inline EXPECT markers
│   ├── test_validators.py
│   ├── test_secrets.py
│   ├── test_scanner.py
│   ├── test_walk.py
│   ├── test_handlers.py
│   ├── test_redos.py
│   └── test_properties.py
├── docs/
│   ├── WORKFLOW.md              product architecture
│   ├── IMPLEMENTATION.md        this file
│   └── HOOK-CONTRACT.md         observed platform behaviour + version
├── README.md
└── LICENSE
```

---

## 4. Call path — prompt scan

```mermaid
flowchart TB
    A["Claude Code writes JSON to stdin"] --> B["run.sh: command -v python3"]
    B -->|absent| Z0["exit 0, silent"]:::exit
    B -->|present| C["exec python3 -S -E scan.py"]
    C --> D["cli.py: json.loads(stdin)"]
    D --> E["read hook_event_name"]
    E --> F["handlers/user_prompt_submit.py"]
    F --> G["secrets.py: parse secrets.txt"]
    G --> H["scanner.scan(prompt, enabled)"]
    H --> I["detectors.finditer per class"]
    I --> J["validators.check per candidate"]
    J --> K["resolve.longest_wins"]
    K --> L{"any spans?"}
    L -->|no| Z1["exit 0, empty stdout<br/>prompt sent unchanged"]:::exit
    L -->|yes| M["audit.write — HMAC only"]
    M --> N{"mode"}
    N -->|detect| Z2["exit 0, logged only"]:::exit
    N -->|guard| O["stdout: decision block + reason"]:::block

    classDef exit fill:#2a3a4a,stroke:#4a90c9,color:#d2e4f0
    classDef block fill:#4a2a2a,stroke:#c94227,color:#f0d2d2
```

---

## 5. Call path — tool output rewrite

The only path that modifies what the model sees.

```mermaid
flowchart TB
    A["stdin: tool_name + tool_response"] --> B["handlers/post_tool_use.py"]
    B --> C["read payload tool_response<br/>NOT tool_output"]
    C --> D["walk.deep_redact(obj)"]

    D --> E{"node type"}
    E -->|str| F["scanner.scan then redact"]
    E -->|dict| G["recurse each value<br/>keys preserved"]
    E -->|list| H["recurse each item"]
    E -->|"int, bool, null"| I["untouched"]
    G --> E
    H --> E

    F --> J["apply spans RIGHT TO LEFT"]
    J --> K["recompute numLines if content changed"]
    K --> L{"bytes actually changed?"}
    L -->|no| M["emit NOTHING"]:::exit
    L -->|yes| N["stdout: updatedToolOutput + additionalContext"]
    N --> O["Claude Code: outputSchema.safeParse"]
    O -->|fail| P["rewrite DISCARDED<br/>original output used"]:::bad
    O -->|pass| Q["model receives cleaned output"]:::good

    classDef exit fill:#2a3a4a,stroke:#4a90c9,color:#d2e4f0
    classDef bad fill:#4a2a2a,stroke:#c94227,color:#f0d2d2
    classDef good fill:#2a4a33,stroke:#27c96b,color:#d2f0dd
```

Three implementation rules this path enforces:

| Rule | Why |
|---|---|
| Read `tool_response` | `tool_output` yields `undefined` — the scanner finds nothing and every secret passes, indistinguishable from "clean" |
| Substitute right-to-left | Left-to-right shifts every later offset and corrupts the output |
| Never emit an identity rewrite | Hooks run in parallel, last write wins — an unchanged copy can clobber another plugin's real redaction |

---

## 6. Secrets file parsing

```mermaid
flowchart TB
    F["secrets.txt"] --> R["read lines"]
    R --> L{"line shape"}
    L -->|"empty or starts with hash"| SKIP["skip"]
    L -->|"starts and ends with slash"| RX["compile regex"]
    L -->|"starts and ends with quote"| LIT["literal matcher"]
    L -->|bare word| NAME{"known detector?"}

    NAME -->|yes| ON["enable it"]
    NAME -->|no| WARN["stderr warning<br/>CONTINUE, do not fail"]:::warn

    RX --> VRX{"compiles?"}
    VRX -->|yes| ADD["add to active set"]
    VRX -->|no| WARN

    LIT --> ADD
    ON --> ADD
    ADD --> SET["active detector set"]

    F -.->|"missing or unreadable"| DEF["fall back to default-secrets.txt"]:::warn
    DEF --> SET

    classDef warn fill:#4a3f2a,stroke:#c9a227,color:#f0e6d2
```

**A malformed config must never block a session.** Every failure path degrades to a warning.

---

## 7. Detector and validator matrix

```mermaid
flowchart LR
    subgraph D["Enabled by default — credentials"]
        D1["aws_key"] --> V1["entropy on paired secret"]
        D2["github_token"] --> V0["length only"]
        D3["anthropic_key"] --> V0
        D4["slack_token"] --> V0
        D5["private_key"] --> V2["matching END block"]
        D6["jwt"] --> V3["header decodes to JSON"]
        D7["db_uri"] --> V4["password real, not placeholder"]
        D8["credit_card"] --> V5["Luhn + IIN, minus test PANs"]
    end

    subgraph P["Commented out — personal data"]
        P1["email"] --> V6["domain not example.com"]
        P2["phone"] --> V7["length, reject 555-01xx"]
        P3["ip_address"] --> V8["public only"]
        P4["dob"] --> V9["plausible year"]
    end
```

| Class | Anchored | Why anchoring matters |
|---|---|---|
| `aws_key`, `github_token`, `anthropic_key`, `slack_token`, `jwt` | ✅ | Literal prefix → linear time → safe on oversized input |
| `private_key` | ✅ | Literal `BEGIN` marker |
| `db_uri`, `credit_card`, `email`, `phone`, `ip_address`, `dob` | ❌ | Subject to size and line caps |

---

## 8. Data model

```mermaid
classDiagram
    class Span {
        +int start
        +int end
        +str name
        +str text
    }
    class Detector {
        +str name
        +str tier
        +Pattern pattern
        +callable validator
        +bool anchored
    }
    class SecretsFile {
        +set~str~ classes
        +list~str~ literals
        +list~Pattern~ patterns
        +list~str~ warnings
    }
    class Config {
        +str mode
        +bool audit
        +SecretsFile secrets
    }
    class AuditRecord {
        +str ts
        +str event
        +str tool
        +str action
        +list hits
    }
    Detector ..> Span : produces
    SecretsFile --> Detector : enables
    Config o-- SecretsFile
    Span ..> AuditRecord : hashed into
```

`AuditRecord.hits` holds `{class, id}` where `id = HMAC-SHA256(salt, value)[:12]`. **The value
itself is never stored** — and a plain hash is not used either, because `sha256` of a date of birth
or a card number is brute-forceable in seconds.

---

## 9. State file lifecycle

```mermaid
flowchart TB
    I["plugin install"] --> SS["SessionStart hook"]
    SS --> C1{"secrets.txt exists?"}
    C1 -->|no| CP["copy default-secrets.txt"]
    C1 -->|yes| KEEP1["leave untouched"]
    SS --> C2{"salt exists?"}
    C2 -->|no| GEN["urandom 32 bytes, mode 0600"]
    C2 -->|yes| KEEP2["reuse"]

    CP --> DATA
    KEEP1 --> DATA
    GEN --> DATA
    KEEP2 --> DATA
    DATA[("CLAUDE_PLUGIN_DATA<br/>secrets.txt · policy.json<br/>salt · audit.jsonl")]

    UPD["plugin update / git pull"] --> ROOT["CLAUDE_PLUGIN_ROOT<br/>REPLACED"]:::bad
    UPD --> DATA2["CLAUDE_PLUGIN_DATA<br/>SURVIVES"]:::good

    classDef bad fill:#4a2a2a,stroke:#c94227,color:#f0d2d2
    classDef good fill:#2a4a33,stroke:#27c96b,color:#d2f0dd
```

Anything user-owned lives in `CLAUDE_PLUGIN_DATA`. Writing config into the plugin root loses it on
every update.

---

## 10. Failure paths

```mermaid
flowchart TB
    START["hook invoked"] --> P{"python3 present?"}
    P -->|no| A["exit 0 silently<br/>SessionStart warns once per install"]:::safe
    P -->|yes| RUN["run scan"]
    RUN --> E{"exception?"}
    E -->|no| OK["normal verdict"]:::safe
    E -->|yes| CATCH["except BaseException"]
    CATCH --> W["stderr: guard did NOT run"]
    W --> X["exit 0, empty stdout"]:::safe

    CATCH -.->|NEVER| BAD["exit 2"]:::bad
    BAD --> WHY["exit 2 means BLOCK —<br/>a crash must not read as a deliberate deny"]

    RUN --> T{"exceeds 5s timeout?"}
    T -->|yes| KILL["Claude Code kills it<br/>session continues"]:::safe

    classDef safe fill:#2a4a33,stroke:#27c96b,color:#d2f0dd
    classDef bad fill:#4a2a2a,stroke:#c94227,color:#f0d2d2
```

**Fail open, loudly.** A silent failure is worse than either alternative — it manufactures false
confidence in a tool people installed to stop worrying.

---

## 11. Bounded work — ReDoS defence

Python's `re` has **no timeout**. A backtracking pattern would hang for the full hook timeout.

```mermaid
flowchart LR
    IN["input text"] --> S{"size"}
    S -->|"over 1 MB"| A["anchored patterns only<br/>log the degradation"]
    S -->|normal| L{"per line"}
    L -->|"over 4 KB"| SKIP["skip unanchored patterns<br/>minified and base64 live here"]
    L -->|normal| FULL["all enabled patterns"]
    A --> OUT["spans"]
    SKIP --> OUT
    FULL --> OUT
```

| Guard | Value | Without it |
|---|---|---|
| `hooks.json` timeout | 5 s | The 600 s default freezes a session for ten minutes with no explanation |
| Input cap | 1 MB | A 50 MB log dump scans in full |
| Line cap | 4 KB | Minified bundles trigger pathological backtracking |

---

## 12. Test coverage map

```mermaid
flowchart LR
    T1["test_validators"] --> M1["validators.py"]
    T2["test_secrets"] --> M2["secrets.py"]
    T3["test_scanner"] --> M3["scanner.py + resolve.py + detectors.py"]
    T4["test_walk"] --> M4["walk.py + redact.py"]
    T5["test_handlers"] --> M5["handlers/ + cli.py"]
    T6["test_redos"] --> M3
    T7["test_properties"] --> M4
    F["tests/fixtures<br/>real Step 0 payloads"] --> T4
    F --> T5
    C["tests/corpus<br/>EXPECT markers"] --> T3
    C --> CC["tools/corpus_check<br/>precision + recall"]
```

| Test | Asserts |
|---|---|
| `test_validators` | `5432` is not a card; `4242…` is excluded; `127.0.0.1` is not a hit |
| `test_secrets` | Unknown word warns; bad regex skipped; missing file falls back |
| `test_scanner` | Nested spans resolved; caps honoured |
| `test_walk` | Every key and type survives; rewrite passes schema validation |
| `test_handlers` | Fixture in → exact JSON out |
| `test_redos` | 1 MB adversarial input inside the bound |
| `test_properties` | Never crashes; never drops non-secret text |

Run with `python3 -m unittest discover tests/` — no packages to install.

---

## 13. Release checklist

```mermaid
flowchart TB
    A{"measured P/R recorded?"} -->|no| STOP["do not ship default-on"]:::bad
    A -->|yes| B{"p95 under 25 ms?"}
    B -->|no| OPT["optimise or flatten layout"]
    B -->|yes| C{"fail-open verified?"}
    C -->|yes| D{"no-python3 path verified?"}
    D -->|yes| E{"placeholders filled?"}
    E -->|yes| F{"in-development banner removed?"}
    F -->|yes| G["tag v0.1.0<br/>point marketplace at the tag"]:::good

    classDef bad fill:#4a2a2a,stroke:#c94227,color:#f0d2d2
    classDef good fill:#2a4a33,stroke:#27c96b,color:#d2f0dd
```

Pinning the marketplace entry at a tag rather than a branch means a push to `main` does not ship
straight to every installed user — which matters more for a security tool than for most software.
