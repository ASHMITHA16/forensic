# Memory Dump Analysis Agent — Design Proposal (Phase 0)

**Component:** Memory Analysis Agent
**Parent system:** AI-Based Multi-Agent Digital Forensics Framework (AutoGen)
**Status:** Awaiting approval — no code written yet
**Date:** 2026-08-26

---

## 1. Architecture and Justification

### 1.1 The governing principle: three-tier separation

The agent is built as three strictly separated tiers. This single decision is what makes the rest of the requirements (evidence integrity, reproducibility, observation-vs-interpretation) achievable rather than aspirational.

```
                  ┌──────────────────────────────────────────┐
   memory dump ──▶│  TIER 1 — ACQUISITION & EXECUTION        │
   (read-only)    │  seal → identify OS → plan → run vol3     │
                  │  Output: raw plugin JSON + audit log      │
                  └────────────────────┬─────────────────────┘
                                       │ raw rows
                  ┌────────────────────▼─────────────────────┐
                  │  TIER 2 — NORMALIZATION                   │
                  │  raw rows → typed OBSERVATIONS            │
                  │  Judgement-free. Every record carries     │
                  │  provenance (plugin, row, offset).        │
                  └────────────────────┬─────────────────────┘
                                       │ observations
                  ┌────────────────────▼─────────────────────┐
                  │  TIER 3 — DETECTION & SYNTHESIS           │
                  │  rules → FINDINGS → timeline → IOCs       │
                  │  Never touches the dump. Cites obs_ids.   │
                  └────────────────────┬─────────────────────┘
                                       │
                              memory_agent_output.json
                                       │
                                       ▼
                            Correlation & Reasoning Agent
```

**Tier 1 never interprets. Tier 3 never reads the dump.**

Why this is the right shape:

| Property | How the separation delivers it |
|---|---|
| **Evidence defensibility** | Every finding walks backward: `finding → obs_id → plugin + row_index + physical offset → dump`. No conclusion is orphaned from its evidence. |
| **Testability without a dump** | Tier 3 consumes JSON. Detection rules are unit-tested against fixture observation files on any laptop — no 4 GB memory image, no Volatility install. Critical for iterating on your project machine. |
| **Reproducibility** | Tier 1 is I/O; Tiers 2–3 are pure functions. Same dump + same rule-pack version ⇒ byte-identical output. This is the repeatability property the report claims but does not currently engineer. |
| **Failure isolation** | A Volatility plugin that crashes or hangs on a malformed dump degrades coverage; it does not abort the investigation. |
| **Extensibility** | Adding Linux support = new extractors in Tier 2. Rules in Tier 3 operate on the normalized model and are largely OS-agnostic. |

### 1.2 Why subprocess-based Volatility 3, not the Python API

`vol -r json -f <dump> <plugin>` invoked as a subprocess, per approval.

- **Crash isolation.** Vol3 plugins raise on truncated/hibernation-compressed/corrupted dumps with real frequency. A process boundary contains it; an in-process `SymbolError` would kill the agent mid-run.
- **Enforced timeouts.** `windows.filescan` and `windows.handles` can run for many minutes on a large dump. A subprocess can be killed at a wall-clock budget; an in-process call cannot be safely interrupted.
- **Chain-of-custody clarity.** The exact `argv` is a first-class, loggable artifact. "This finding came from *this literal command*" is an auditable statement — far stronger than "we called this internal API."
- **Version stability.** Vol3's internal APIs shift between minor releases; the CLI + JSON renderer contract is stable.

Cost: each plugin re-scans the dump. Mitigation is a shared `--cache-path` under the case workspace so Vol3 reuses its scan cache across invocations, plus concurrent execution of independent plugins.

### 1.3 Why deterministic detection, with no LLM inside this agent

Per approval, the memory agent emits **facts and rule-derived findings only**. LLM reasoning lives downstream in the Correlation Agent, exactly as your report's architecture describes.

Rationale: an LLM in the extraction path makes every output non-reproducible and unfalsifiable. If the correlation agent consumes probabilistic text from a probabilistic upstream, confidence scores compound meaninglessly. Keeping this agent deterministic means the correlation agent reasons over *evidence*, not over another model's guesses — and any disputed finding can be re-derived by hand from the cited plugin row.

Every rule carries `rule_id`, `rule_version`, and its literal threshold. A reviewer can disagree with a threshold; they cannot dispute what the rule did.

### 1.4 Module layout

```
memory_agent/
├── core/
│   ├── evidence.py       # hashing, read-only guard, chain of custody
│   ├── audit.py          # append-only JSONL audit log, self-sealing
│   ├── profile.py        # OS/kernel identification
│   ├── runner.py         # Volatility3 subprocess wrapper + timeouts
│   ├── planner.py        # OS → plugin execution plan
│   └── schema.py         # Pydantic models — THE CONTRACT
├── extractors/           # Tier 2: plugin rows → observations
│   ├── processes.py  network.py  commands.py
│   ├── modules.py    injection.py  services.py
├── detectors/            # Tier 3: observations → findings
│   ├── engine.py         # rule runner, confidence arithmetic
│   └── rules/            # process.py network.py command.py injection.py
├── synthesis/
│   ├── timeline.py       # temporal + sequence-hint reconstruction
│   └── iocs.py           # IOC extraction, allowlisting, defanging
├── report.py             # envelope assembly + schema validation
├── cli.py                # standalone entry point
└── autogen_adapter.py    # thin AssistantAgent registration (~50 LOC)
```

The core package has **zero AutoGen and zero LLM dependency**. `autogen_adapter.py` is the only file that imports AutoGen — it registers `analyze_memory_dump(dump_path, case_id) -> dict` as a tool function. You can demo, test, and defend the agent without an API key.

---

## 2. Evidence Integrity and Read-Only Handling

### 2.1 Sealing protocol

1. **Pre-analysis seal.** Stream the dump in 8 MiB chunks; compute SHA-256 (primary) and MD5 (legacy cross-tool comparison only — recorded, never trusted alone). Record `size_bytes`, `st_mtime_ns`, `st_ino`, `st_dev`.
2. **Read-only enforcement.** Open via `os.open(path, os.O_RDONLY)`. The dump path is passed to Volatility only as an input argument; Vol3's cache, symbol, and output directories are all redirected to an isolated case workspace so nothing is written beside the evidence.
3. **Post-analysis verification.** Recompute SHA-256 and re-stat. `integrity_verified = (sha_before == sha_after) and (inode/mtime unchanged)`. A mismatch sets `integrity_verified: false`, raises `EvidenceTampered`, and the run is marked `INVALID` — findings are still emitted but flagged non-admissible.
4. **Tamper-evident audit log.** Every step (start, argv, exit code, duration, hash, error) appends one JSON line to `audit.jsonl`. At completion the log itself is hashed; `audit.log_sha256` goes into the output envelope. Altering the audit trail after the fact breaks the seal.

### 2.2 Chain of custody record

Captured at run start and embedded in the output: `case_id`, `evidence_id`, `investigator`, `acquisition_time`/`tool`/`method` (if supplied), analysis host fingerprint, analysis start/end UTC, Volatility version, Python version, rule-pack version, `run_id` (UUIDv4).

### 2.3 Offline by default

No external network calls (no VirusTotal, no threat-intel lookups) in the default path. Evidence-derived data never leaves the analysis host unless explicitly enabled — a hard requirement for real casework and a defensible design choice in your report.

---

## 3. OS Identification and Toolchain

### 3.1 Identification cascade

1. `windows.info.Info` → on success: version, build, architecture, DTB, KdVersionBlock, **and the dump's own system time**.
2. On failure → `banners.Banners` → Linux/macOS kernel banner string, mapped to a required ISF symbol table.
3. On failure → raw signature scan for known kernel strings.
4. On total failure → `os_family: "unknown"`, run aborts before plugin execution with a structured error rather than emitting garbage.

Output includes `confidence` and `determined_by` (which method won).

**Clock anchoring — a detail that matters.** The dump's `SystemTime` is captured and all memory timestamps are normalized to UTC against *it*, not against the analysis host clock. Any known skew between the acquisition host and true UTC is recorded as `clock_skew_seconds`. Without this, your correlation agent will silently misalign memory events against disk MFT timestamps and network PCAP timestamps — and produce a confidently wrong timeline.

### 3.2 Windows plugin map (Phase 1)

| Domain | Plugins | Purpose |
|---|---|---|
| Environment | `windows.info` | OS, build, arch, system time |
| Processes | `windows.pslist`, `windows.psscan`, `windows.pstree`, `windows.psxview` | Active list, pool-scan carve, hierarchy, **cross-view hidden-process detection** |
| Commands | `windows.cmdline`, `windows.consoles`, `windows.cmdscan` | Full command lines, console scrollback, typed history |
| Network | `windows.netscan`, `windows.netstat` | Sockets, connections, owning PID, socket create time |
| Modules/DLLs | `windows.dlllist`, `windows.ldrmodules`, `windows.modules`, `windows.modscan`, `windows.driverscan` | Loaded DLLs, **PEB unlink detection**, kernel modules, hidden drivers |
| Injection | `windows.malfind`, `windows.vadinfo`, `windows.hollowprocesses`* | RWX private VADs, PE headers in anonymous memory, hollowing |
| Services | `windows.svcscan` | Service binaries, persistence |
| Optional | `windows.handles`, `windows.mutantscan`, `windows.filescan`, `windows.registry.hivelist` | Expensive — behind a `--deep` flag |

\* availability varies by Vol3 version; planner probes and degrades gracefully.

Plugin failures are recorded per-plugin in `execution[]` with status `ok | failed | timeout | unavailable` and reflected in `coverage`. **Partial results are always emitted** — never all-or-nothing.

---

## 4. Analysis Pipeline

| Stage | Name | Output |
|---|---|---|
| S0 | Acquire & seal | Hashes, chain of custody, audit log opened |
| S1 | Identify OS | `environment` block |
| S2 | Plan | Ordered plugin list with per-plugin timeouts |
| S3 | Execute | Raw plugin JSON + `execution[]` records |
| S4 | Normalize | `observations` — typed, provenance-tagged, judgement-free |
| S5 | Detect | `findings` — rule-derived, citing `obs_ids` |
| S6 | Timeline | `timeline[]` — anchored, precision-labelled |
| S7 | IOC extraction | `iocs[]` — allowlisted, deduplicated |
| S8 | Seal & emit | Post-hash verify, audit hash, schema validation, envelope |

### 4.1 Detection rule pack v1

| Rule ID | Detection | Core signal |
|---|---|---|
| MEM-P-001 | Hidden process | Present in `psscan`/`psxview`, absent from `pslist` |
| MEM-P-002 | Exited process holding sockets | `ExitTime` set but owns an active connection |
| MEM-P-003 | Masqueraded system process | `svchost.exe`/`lsass.exe` with non-canonical parent |
| MEM-P-004 | System binary, wrong path | `csrss.exe` outside `\Windows\System32` |
| MEM-P-005 | Orphaned process | PPID not resident and not a known exit |
| MEM-P-006 | Duplicated singleton | >1 instance of `lsass.exe` / `wininit.exe` |
| MEM-I-001 | Code in private RWX memory | `malfind`: private VAD, PAGE_EXECUTE_READWRITE, `MZ` header |
| MEM-I-002 | PEB-unlinked DLL | `ldrmodules` InLoad/InInit/InMem mismatch |
| MEM-I-003 | Process hollowing indicator | VAD-backed path ≠ EPROCESS image path |
| MEM-N-001 | External established connection | Non-RFC1918 foreign address, state ESTABLISHED |
| MEM-N-002 | Unexpected listener | LISTENING socket owned by a non-service user process |
| MEM-N-003 | Suspicious port | 4444/1337/8080/9001 with non-browser owner |
| MEM-C-001 | Obfuscated PowerShell | `-enc`, `-w hidden`, `-nop`, `Bypass` in command line |
| MEM-C-002 | LOLBin abuse | `certutil -urlcache`, `bitsadmin /transfer`, `mshta http` |
| MEM-C-003 | Discovery burst | Clustered `whoami`/`net user`/`ipconfig`/`systeminfo` |
| MEM-M-001 | Hidden kernel module | Present in `modscan`, absent from `modules` |
| MEM-S-001 | Suspicious service binary | `svcscan` path under `\Temp`, `\AppData`, or `\Users\Public` |

**Confidence arithmetic (explicit, not learned):**
`confidence = clamp(base_confidence + Σ corroboration_bonus, 0.0, 0.95)`
Capped at 0.95 — this agent never asserts certainty. `confidence_basis` states the arithmetic in plain text on every finding.

### 4.2 Timeline — an honest constraint

Memory dumps yield genuinely few real timestamps: process create/exit times, socket creation times, some handle and service timestamps. Most artifacts have **none**.

Rather than fabricate ordering, every timeline event carries `precision`:

- `exact` — a real timestamp from the artifact
- `approximate` — derived, bounded by neighbouring events
- `relative` — no timestamp; ordering inferred from PID monotonicity / EPROCESS pool layout, expressed as `sequence_hint` only
- `unknown` — present in the dump, not placeable in time

The correlation agent must be told which is which, or it will anchor cross-domain sequences on inferences. Flagging this explicitly is a strength of the design, not a limitation to hide.

---

## 5. Input / Output Contracts

### 5.1 Input contract

```python
analyze_memory_dump(
    dump_path: str,           # required — absolute path, must exist, readable
    case_id: str,             # required — e.g. "DF-2026-001"
    evidence_id: str = None,  # auto-generated if absent
    investigator: str = None,
    acquisition: dict = None, # {acquired_utc, tool, method}
    deep: bool = False,       # enable expensive plugins
    plugin_timeout_s: int = 300,
    output_dir: str = None,
) -> dict                     # the envelope below
```

Preconditions enforced before any work: path exists, is a regular file, is readable, size > 0, and (warning only) size is plausible for a memory image.

### 5.2 Output contract — envelope

```jsonc
{
  "schema_version": "1.0.0",
  "agent":   { "name": "memory_analysis_agent", "version": "1.0.0",
               "run_id": "uuid4", "started_utc": "...", "completed_utc": "...",
               "status": "COMPLETE | PARTIAL | INVALID" },
  "case":    { "case_id": "DF-2026-001", "investigator": "..." },
  "evidence": {
    "evidence_id": "EV-MEM-01", "file_name": "...", "size_bytes": 0,
    "hashes": { "sha256_before": "...", "sha256_after": "...", "md5": "...",
                "integrity_verified": true },
    "read_only_enforced": true,
    "acquisition": { "acquired_utc": null, "tool": null, "method": null }
  },
  "environment": {
    "os": { "family": "windows", "version": "10.0.19041", "arch": "x64",
            "build": "19041", "confidence": 0.99, "determined_by": "windows.info" },
    "dump_system_time_utc": "2026-04-12T02:22:11Z",
    "clock_skew_seconds": null,
    "toolchain": { "volatility": "2.7.0", "python": "3.11.6", "rule_pack": "v1.0" }
  },
  "execution": [
    { "plugin": "windows.pslist", "argv": ["vol","-r","json","-f","...","windows.pslist"],
      "exit_code": 0, "duration_s": 12.4, "row_count": 87, "status": "ok" }
  ],
  "observations": {
    "processes": [], "network": [], "commands": [],
    "modules": [], "injections": [], "services": []
  },
  "findings": [],
  "timeline": [],
  "iocs": [],
  "coverage": { "plugins_attempted": 18, "plugins_succeeded": 17,
                "plugins_failed": 1, "artifact_counts": {} },
  "limitations": [],
  "audit": { "log_path": "...", "log_sha256": "...", "entries": 142 }
}
```

### 5.3 Observation record (example: process)

```jsonc
{
  "obs_id": "OBS-PROC-0007",
  "type": "process",
  "provenance": { "plugin": "windows.pslist", "row_index": 7, "offset": "0x8a3f2040" },
  "pid": 2456, "ppid": 812, "name": "data_transfer.exe",
  "path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\data_transfer.exe",
  "create_time_utc": "2026-04-12T02:18:03Z", "exit_time_utc": null,
  "threads": 4, "handles": 112, "session_id": 1, "wow64": false,
  "cross_view": { "pslist": true, "psscan": true, "pstree": true, "psxview": true }
}
```

No field on an observation expresses suspicion. `cross_view` is a fact; MEM-P-001 is what turns it into a finding.

### 5.4 Finding record — the observation/interpretation split

```jsonc
{
  "finding_id": "FND-0003",
  "rule_id": "MEM-I-001", "rule_version": "1.0",
  "title": "Executable code in private RWX memory region",
  "category": "code_injection",
  "severity": "HIGH",
  "confidence": 0.86,
  "confidence_basis": "base 0.75 (MZ header in private PAGE_EXECUTE_READWRITE VAD); +0.11 corroborated by MEM-N-001 on same PID",
  "observation_refs": ["OBS-INJ-0001", "OBS-PROC-0007"],
  "entities": { "pids": [2456], "processes": ["data_transfer.exe"],
                "ips": ["185.77.22.90"], "files": [] },
  "first_seen_utc": "2026-04-12T02:18:03Z",
  "mitre_attack": ["T1055.002"],

  "observation_statement": "The VAD at 0x2a0000 in PID 2456 is private, marked PAGE_EXECUTE_READWRITE, and its first two bytes are 0x4D 0x5A.",
  "interpretation": "Consistent with reflective PE injection into a running process.",
  "alternative_explanations": ["JIT compilation by a .NET or JavaScript engine",
                               "A legitimate packed or self-extracting installer"],
  "analyst_action": "Dump the VAD region and submit for static analysis."
}
```

**This four-field structure is the mechanism** that satisfies "clearly separates observations from interpretations":

- `observation_statement` — a fact, verifiable directly against the dump. Contains no judgement words.
- `interpretation` — what it may mean. Hedged, and always separable from the fact.
- `alternative_explanations` — mandatory, non-empty. Forces the design to acknowledge benign causes and prevents the downstream LLM from treating a finding as settled.
- `analyst_action` — what a human should do to resolve the ambiguity.

The correlation agent can be instructed to reason over `observation_statement` and `entities` while treating `interpretation` as a hypothesis, not evidence.

### 5.5 Timeline event

```jsonc
{
  "event_id": "TL-0012",
  "timestamp_utc": "2026-04-12T02:18:03Z",
  "precision": "exact",              // exact | approximate | relative | unknown
  "sequence_hint": 12,
  "source_domain": "memory",
  "artifact_type": "process_create",
  "description": "Process data_transfer.exe (PID 2456) created by PID 812",
  "observation_refs": ["OBS-PROC-0007"],
  "finding_refs": ["FND-0003"],
  "entities": { "pids": [2456], "processes": ["data_transfer.exe"] },
  "confidence": 0.95
}
```

`source_domain: "memory"` is uniform across every event — this is the field your correlation agent merges on when interleaving disk, log, and network timelines.

### 5.6 IOC record

```jsonc
{
  "ioc_id": "IOC-0004",
  "type": "ipv4",   // ipv4 | ipv6 | domain | url | filepath | filename
                    // | sha256 | mutex | registry_key | port | process_name
  "value": "185.77.22.90",
  "context": "Foreign address of an ESTABLISHED socket owned by PID 2456 (data_transfer.exe)",
  "observation_refs": ["OBS-NET-0011"],
  "finding_refs": ["FND-0003"],
  "confidence": 0.80,
  "false_positive_risk": "low"
}
```

IOC hygiene: RFC1918 / loopback / multicast / broadcast addresses are allowlisted out; Microsoft and OS-vendor ranges are optionally allowlisted; values are deduplicated case-insensitively; a `--defang` export option is available.

---

## 6. Proposed Phase Plan

| Phase | Scope | Deliverable |
|---|---|---|
| **1** | `core/evidence.py`, `core/audit.py`, project skeleton, CLI shell | `python -m memory_agent verify <dump>` — hashes, seals, writes chain of custody. Runs with no Volatility installed. |
| **2** | `core/runner.py`, `core/profile.py`, `core/planner.py` | OS identification + plugin execution with timeouts, raw JSON captured, `execution[]` populated |
| **3** | All six extractors + `core/schema.py` | Full `observations` block, Pydantic-validated |
| **4** | `detectors/engine.py` + rule pack v1 (17 rules) | `findings[]` with the four-field split; unit-tested against JSON fixtures |
| **5** | `synthesis/timeline.py`, `synthesis/iocs.py`, `report.py` | Complete validated envelope |
| **6** | `autogen_adapter.py`, test suite, fixture corpus, docs | Registered AssistantAgent tool + reproducibility test |

Each phase ends with runnable code and a test you can execute. Phases 3–5 are testable without a real memory dump using captured fixtures — worth building the fixture corpus in Phase 2 so the rest of the work isn't gated on dump availability.

---

## 7. Two notes on the Phase-II report

1. **Section 1.2 (Problem Statement)** currently contains text about Gen Z consumer purchasing habits and sustainable fashion — clearly a paste from a different document. It should state the digital forensics problem.
2. **Section 3.4** ("Memory Analysis Findings") is mis-nested: "3.4.1 Network Analysis Agent Results" appears as its subsection. It should be 3.3.5 and 3.3.6 respectively, consistent with the other agent-level results.
