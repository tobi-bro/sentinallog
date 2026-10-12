# SentinelLog — System Architecture & Design Specification

**Document Version:** 1.0.0  
**Application Version:** 2.4.0  
**Author:** Tobi  

---

## 1. High-Level System Architecture

SentinelLog is structured as a decoupled, multi-layered defensive security pipeline designed to transform raw application and authentication logs into actionable security incidents.

```
Raw Log Stream (Disk / Memory / HTTP Upload)
                    │
                    ▼
     ┌─────────────────────────────┐
     │ 1. Secure Ingestion Layer   │  [sentinellog/ingestion.py]
     │    - Size boundary limits   │
     │    - Streaming generators   │
     │    - Encoding resilience    │
     └──────────────┬──────────────┘
                    │
                    ▼
     ┌─────────────────────────────┐
     │ 2. Parsing & Normalization  │  [sentinellog/parser.py]
     │    - IPv4 regex + 0-255 octets
     │    - ISO timestamp parsing  │
     │    - Severity classification│
     └──────────────┬──────────────┘
                    │
                    ▼
     ┌─────────────────────────────┐
     │ 3. Threat Detection Engine  │  [sentinellog/rules.py]
     │    - RULE-AUTH-001 (Failed) │
     │    - RULE-AUTH-002 (Unauth) │
     │    - Rolling time windows   │
     └──────────────┬──────────────┘
                    │
                    ▼
     ┌─────────────────────────────┐
     │ 4. Incident Correlator      │  [sentinellog/correlator.py]
     │    - Same-IP grouping       │
     │    - Bounded window rule    │
     │    - Anti-chaining filter   │
     │    - Deterministic UUIDv5   │
     └──────────────┬──────────────┘
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
┌──────────────────┐  ┌──────────────────────────────────┐
│ 5. Reporting     │  │ 6. Delivery Layers               │
│ [reporting.py]   │  │    - Interactive CLI (main.py)   │
│ - Atomic JSON    │  │    - FastAPI Service (api.py)    │
│ - Markdown summ. │  │    - Web SOC Dashboard (static/) │
└──────────────────┘  └──────────────────────────────────┘
```

---

## 2. Layer Responsibilities

### Layer 1: Secure Ingestion (`sentinellog/ingestion.py`)
- **Memory Footprint:** Uses Python generators (`yield`) to stream lines from disk without loading complete multi-gigabyte files into RAM ($O(1)$ spatial complexity).
- **Security Bounds:** Enforces `max_file_size_bytes` (50 MB default) and `max_line_length` (4,096 chars default) to prevent buffer exhaustion and ReDoS attacks.
- **Encoding Safety:** Opens files with `errors="replace"` to handle corrupted byte streams gracefully.

### Layer 2: Parsing & Normalization (`sentinellog/parser.py`)
- Extracts timestamps conforming to `%Y-%m-%d %H:%M:%S` or `%Y-%m-%dT%H:%M:%S`.
- Validates IPv4 addresses using regular expressions combined with numerical octet verification ($0 \le \text{octet} \le 255$), rejecting out-of-range strings like `999.999.999.999`.
- Categorizes event severity into `INFO`, `WARNING`, `ERROR`, or `UNKNOWN`.

### Layer 3: Threat Detection (`sentinellog/rules.py`)
- Evaluates event sequences against configurable threshold rules.
- Tracks source IPs within rolling time windows (`find_threshold_event`).
- Creates structured security alerts with unique UUID identifiers, timestamps, rule IDs, and human-readable investigation explanations.

### Layer 4: Incident Correlation (`sentinellog/correlator.py`)
- Groups related security alerts by matching source IPv4 addresses within a rolling 5-minute correlation window.
- **Bounded Window Rule (Anti-Chaining):** Guarantees that every alert cluster strictly satisfies $\Delta t \le \text{window\_minutes}$, preventing transitive chaining from merging events occurring hours apart.
- Generates RFC 4122 v5 deterministic UUIDs seeded by IP and constituent alert evidence.

### Layer 5: Delivery & Reporting (`sentinellog/reporting.py`, `main.py`, `sentinellog/api.py`)
- **CLI Mode:** Terminal menu and batch processing flags.
- **REST API:** FastAPI application providing headless JSON triage endpoints.
- **Web Dashboard:** Single-page application providing dark-mode SOC visualization, timeline inspection, and report downloads.
