# Correlation & Reasoning Agent — Design

**Component:** Correlation & Reasoning Agent (`correlation_agent/`)
**Parent system:** AI-Based Multi-Agent Digital Forensics Framework (AutoGen)
**Upstream:** Log, Network, Memory and Disk agents
**Schema:** 1.0.0 · **Rule pack:** COR-v1.0 · **Agent version:** 1.0.0

---

## 1. What it is for, and the contract it inherits

Each analysis agent looks at one evidence domain. This agent answers the
question none of them can: **which of these findings describe the same
activity?** It turns four lists of findings into one evidence-cited account:
correlations, the attack chain they form, and two competing hypotheses.

The memory agent's design names this agent as its consumer
(`memory_agent/docs/DESIGN.md` §1.1, §1.3, §3.1, §4.2, §5.4–5.5) and its
AutoGen adapter spells out how its output must be read. This agent is built to
that contract:

| Requirement from the upstream design | How it is met |
|---|---|
| Python, same tiered build, zero dependencies, AutoGen only at the edge | A stdlib-only package, layout mirroring `memory_agent/`. `autogen_adapter.py` is the only file that knows AutoGen exists, and it imports AutoGen lazily. |
| Consume `memory_agent_output.json` | The preferred memory input is the envelope itself (`envelope_path`). The Node summary's `meta.envelopePath` is followed automatically. |
| Reason over `observation_statement`; treat `interpretation` as a hypothesis | Every correlation has its own four-field split: observation (citing evidence refs), interpretation, alternative explanations, analyst action. |
| `alternative_explanations` never empty | Every rule ships benign explanations. `core/schema.py` rejects an envelope where one is empty. |
| `agent.status: INVALID` ⇒ not admissible | Becomes `admissible: false` on every correlation citing that domain, with a −0.20 confidence term and halved risk weight. |
| Read `limitations` before concluding from an absence | A missing domain makes its rules `not_evaluated`, and that is written into `limitations`. The schema rejects an envelope that fails to say so. |
| Only `exact` (and bounded `approximate`) times on a cross-domain timeline | Untimed findings are counted in `untimed_findings`, never given a synthetic time. The schema rejects an untimed timeline event. |
| Apply `clock_skew_seconds` or the timeline is confidently wrong | A known memory skew is subtracted (`clock_adjustment_s` on each event). An unknown skew is a stated limitation. |
| Confidence is arithmetic, capped at 0.95 | `clamp(base + Σ adjustments, 0, 0.95)` with every term in `confidence_basis`. |
| Reproducibility scoped to a function (§8.2) | `report.core_digest()` over `deterministic_core()`. The case workspace keeps the exact `input.json`, and re-running it reproduces the digest (tested). |
| Failure isolation | Each rule runs in isolation. One that raises goes into `coverage.rules_errored`, and the rest still run. |

**No LLM inside the agent**, for the reason DESIGN §1.3 gives: a probabilistic
step here would make every correlation unreproducible, and confidence built on
another model's guess compounds into nothing. The reasoning stage is rule-based
and shows its working. An LLM in the AutoGen group calls this agent as a tool
and writes prose *about* the envelope. `TOOL_DESCRIPTION` tells it how to read
the result.

---

## 2. Architecture

```
 log findings ──┐
 net findings ──┤   C1 normalise ─▶ C2 link ─▶ C3 correlate ─▶ C4 timeline ─▶ C5 reason ─▶ C6 assess
 memory_agent_  ┤   evidence items  entities   rule pack      real times     ATT&CK chain  risk, confidence,
  output.json   │   (refs, time,    across     COR-v1         only           H1 vs H0      limitations
 disk findings ─┘   provenance)     domains
                                                                                  │
                                                         correlation_agent_output.json (+ input.json)
```

| Stage | Module | Output |
|---|---|---|
| C1 | `normalise.py` | `evidence_items[]`: one per source finding, ref `LOG-0001` / `NET-…` / `MEM-…` / `DSK-…`. Entities come from structured fields first, then free text (log lines, network detail). The source's own fact, interpretation, alternatives and ATT&CK ids are kept. ATT&CK is inferred only where the agent emits none (`mitre_inferred: true`). |
| C2 | `linking.py` | `entity_links[]`: every entity seen in two or more domains, with a strength (§3.1). |
| C3 | `rules.py`, `engine.py` | `correlations[]`. |
| C4 | `timeline.py` | `timeline[]`, `untimed_findings`. |
| C5 | `reasoning.py` | `attack_chain`, `hypotheses[]`. |
| C6 | `assess.py` | `assessment`, `limitations[]`. |
| — | `correlate.py` | The pipeline, the input contract, the demo payload. |
| — | `report.py` | Digest, compaction, workspace, text summary. |
| — | `core/schema.py` | The contract, validated by hand (no Pydantic, as memory DESIGN §8.1). |
| — | `cli.py`, `autogen_adapter.py` | Entry points. |

**Tiers.** C1–C2 are judgement-free. They normalise and index, and decide
nothing. C3–C6 interpret, and every interpretation cites the evidence items it
rests on, which in turn cite the source finding (`source.id`, e.g.
`FND-0010 MEM-N-001` or `line 8`).

---

## 3. Linking and the rule pack

### 3.1 Link strength

| Entity | Strength | Why |
|---|---|---|
| Public IPv4, domain, full file path | **strong** | Specific enough that a match is unlikely to be chance. |
| Private (RFC1918 / CGNAT) IPv4 | moderate, **−0.10** | Names the local host or a neighbour, which is expected to appear in several sources. |
| Program image, non-executable file name, user | moderate | Names collide. |
| Common system image (`svchost`, `lsass`, `chrome`, `sshd`…), common user (`root`, `system`…), hostname | **weak** | On every host. Listed in `entity_links` and counted in `coverage.weak_links_ignored`, but **never correlated on alone**. |

Loopback, link-local, multicast, broadcast and `0.0.0.0` never link. Paths
from every agent are canonicalised (`C:\Users\X\a.exe`, `Users/X/a.exe` and
`\Device\HarddiskVolume2\Users\X\a.exe` compare equal).

When one activity is linked by several entities (for example `stage2.exe` by
both its full path and its name), the groups merge into one correlation listing
every linking entity. Groups merge only when they share findings in **at least
two domains**. Sharing on one side alone would let a private address present in
every network finding fuse unrelated correlations.

### 3.2 Rule pack COR-v1

| Rule | Domains | Links on | Base | Adjustments |
|---|---|---|---|---|
| **COR-001** Network activity attributable to a process in memory | memory ↔ network | ip, domain | 0.55 | +0.15 threat-intel match, +0.10 beaconing |
| **COR-002** Executable on disk is resident in memory *(→ "Running process backed by a deleted file")* | disk ↔ memory | path, image | 0.50 | +0.15 disk copy deleted, +0.05 CRITICAL memory finding |
| **COR-003** Same address in system logs and network traffic | log ↔ network | ip, domain | 0.45 | +0.15 brute force (or +0.10 failed / unauthorised), +0.10 port scan, +0.10 threat intel |
| **COR-004** Program named in logs is resident in memory | log ↔ memory | image, path | 0.45 | +0.10 command / persistence / malware log event, +0.05 HIGH+ memory finding |
| **COR-005** Address in logs matches a memory network artifact | log ↔ memory | ip, domain | 0.45 | — |
| **COR-006** File referenced in logs is present on disk | log ↔ disk | path, image, file | 0.45 | +0.10 file deleted, +0.10 persistence / command / malware log event |
| **COR-007** Anti-forensic activity in more than one domain | log ↔ disk | *none* | 0.35 | Log Tampering + deleted HIGH+ file. `link_basis: "co-occurrence"`. It says plainly that no entity is shared. |
| **COR-008** Entity observed across multiple evidence domains | any 3+ | any non-weak | 0.55 | +0.10 per domain beyond three |

Terms applied to every correlation:

| Term | Value |
|---|---|
| Linked by a strong identifier | +0.10 |
| Each extra independent shared entity | +0.05 (max +0.15) |
| Only shared address is private | −0.10 |
| A domain's cited findings are all low-confidence at source (< 0.40) | −0.15 |
| Nearest timestamps across the two domains within the window (default 900 s) | +0.10 |
| Nearest timestamps ≥ 24 h apart | −0.10 |
| Cites non-admissible evidence | −0.20 |

Severity is the highest severity among the cited findings, held at MEDIUM when
confidence is below 0.40, so a weak link cannot carry a CRITICAL source to the
top of the list. `python -m correlation_agent rules` prints the pack.

### 3.3 Reasoning (C5)

**Attack chain.** Techniques map to tactics. Phases are listed in ATT&CK order,
and the narrative says that is the textbook order, not the observed one. Where
phases carry real timestamps they are compared, and every disagreement goes
into `order_inversions`.

**Hypotheses.** Always two:

- **H1**, one coordinated intrusion. Base 0.25; up to +0.30 for entity-linked
  correlations, +0.10 if any reach 0.60, up to +0.15 for tactic breadth, +0.05
  for tactics seen in two domains, −0.05 for order inversions, −0.15 for
  non-admissible evidence, −0.05 per missing domain. Clamped to 0.05–0.90.
- **H0**, independent or routine events. The complement of H1, listing the
  correlations that weaken it.

### 3.4 Assessment (C6)

```
risk_score = min(40, Σ per-domain highest severity)              info 0 · low 3 · medium 8 · high 14 · critical 20
           + min(45, Σ correlation severity × confidence)        ×0.5 if non-admissible; low 4 … critical 25
           + min(15, ATT&CK tactics × 2.5)
risk_level = HIGH ≥ 65 · MEDIUM ≥ 35 · LOW
confidence = domains/4 × 0.50 + admissible-domain share × 0.25 + timestamped share × 0.25   (cap 0.95)
```

`confidence` measures how much evidence the assessment stands on, not how
alarming that evidence is.

### 3.5 Admissibility

Per domain and per correlation, `true` / `false` / `null`:

- **false**: memory `INVALID` (replay or failed integrity check), or integrity not verified.
- **true**: memory `COMPLETE`/`PARTIAL` with integrity verified, or a domain whose
  record carries `evidenceHash` (the backend hash-checked it before analysis).
- **null**: not established.

A correlation is `false` if it cites any `false` item, and `true` only if every
item is `true`.

---

## 4. Input and output contracts

### 4.1 Input

```jsonc
{
  "case_id": "DF-2026-001",                                   // optional
  "log":     { "findings": [ … ], "meta": { … }, "provenance": { "analysisId", "fileName", "evidenceHash" } },
  "network": { "findings": [ … ] },
  "memory":  { "envelope_path": ".../memory_agent_output.json" }   // preferred
           | { "envelope": { …memory_agent_output… } }
           | { "findings": [ … ], "meta": { "envelopePath", "status", … } },   // Node summary; envelopePath followed
  "disk":    { "findings": [ … ] }
}
```

The legacy flat shape `{logData, networkData, memoryData, diskData, *Meta}` is
also accepted. A domain counts as **supplied** only with findings, metadata or
an envelope. An empty list alone means "not supplied", never "ran clean".

An explicitly named `envelope_path` that does not exist is an error
(`CA-E-101`). A stored `meta.envelopePath` that has gone is not: the summary
findings are used instead, and `limitations` says so.

### 4.2 Output — `correlation_agent_output.json`

```jsonc
{
  "schema_version": "1.0.0",
  "agent":  { "name": "correlation_agent", "version": "1.0.0", "rule_pack": "COR-v1.0", "run_id": "…",
              "mode": "analyze|demo", "status": "COMPLETE|PARTIAL|INSUFFICIENT", "started_utc": "…", "completed_utc": "…" },
  "case":   { "case_id": "…" },
  "inputs": { "memory": { "supplied": true, "findings": 23, "memory_source": "envelope", "source_status": "INVALID",
                          "admissible": false, "evidence_sha256": "…", "input_sha256": "…" }, "…": {} },
  "evidence_items": [ { "ref": "MEM-0014", "domain": "memory", "source": { "index": 13, "id": "FND-0010 MEM-N-001" },
                        "observation": "…", "interpretation": "…", "timestamp_utc": "…", "precision": "exact",
                        "entities": { "ips": [], "images": [], "paths": [], "pids": [] }, "mitre_attack": [], "admissible": false } ],
  "entity_links": [ { "key": "ip:185.77.22.90", "strength": "strong", "domains": [], "evidence_refs": [] } ],
  "correlations": [ { "correlation_id": "COR-F-0005", "rule_id": "COR-001", "title": "…", "severity": "high",
                      "confidence": 0.55, "confidence_basis": "base 0.55 (COR-001); +0.10 …; −0.20 …",
                      "link_basis": "shared-entity", "linking_entities": [], "evidence_refs": [],
                      "observation_statement": "…", "interpretation": "…", "alternative_explanations": [ "…" ],
                      "analyst_action": "…", "mitre_attack": [], "tactics": [], "admissible": false } ],
  "attack_chain": { "phases": [], "narrative": "…", "order_inversions": [] },
  "hypotheses":   [ { "hypothesis_id": "H1", "confidence": 0.65, "confidence_basis": "…", "supporting": [], "weakening": [] },
                    { "hypothesis_id": "H0", "…": "…" } ],
  "timeline":     [ { "event_id": "CTL-0001", "timestamp_utc": "…", "precision": "exact", "source_domain": "log",
                      "kind": "finding|context", "evidence_ref": "LOG-0001", "correlation_refs": [], "clock_adjustment_s": null } ],
  "untimed_findings": { "log": 0, "network": 6, "memory": 11, "disk": 5 },
  "assessment":   { "risk_level": "HIGH", "risk_score": 100, "risk_basis": [], "confidence": 0.63, "confidence_basis": "…", "admissible": false },
  "coverage":     { "domains_supplied": [], "rules_evaluated": [], "rules_not_evaluated": [], "rules_errored": [], "weak_links_ignored": 0 },
  "limitations":  [],
  "summary": "…",
  "core_digest": "sha256 of deterministic_core()",
  "workspace":    { "run_dir": "…", "input_path": "…", "input_sha256": "…", "envelope_path": "…" }
}
```

`--compact` (what the Node backend stores in History, under MongoDB's 16 MB
document limit) keeps only cited evidence items and the first 1000 timeline
events, and adds `evidence_items_total` / `timeline_total`. A compact envelope
still validates.

### 4.3 Errors

Stable codes, printed as JSON with `--json`:

| Code | Meaning | CLI exit |
|---|---|---|
| `CA-E-100` | Input malformed (not an object, findings not a list, memory envelope is an error record) | 1 |
| `CA-E-101` | Input or memory envelope file not found | 1 |
| `CA-E-102` | Input is not valid JSON | 1 |
| `CA-E-200` | Envelope failed its own contract | 2 |
| `CA-E-300` | Workspace not writable | 1 |
| `CA-E-400` | Demo unavailable (memory_agent replay failed) | 1 |

---

## 5. Integration

**Node backend.** `backend/agents/correlationAgent.js` is a bridge, like
`memoryAgent.js`. It spawns `python -m correlation_agent correlate --input -
-o backend/correlation_cases --json --compact`, writes the payload to stdin,
and adds the pre-existing top-level fields (`riskLevel`, `patterns`, …) for old
callers. Routes:

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/api/analyze/correlate/sources` | Saved agent runs that can be correlated |
| `POST` | `/api/analyze/correlate` | `{ analysisIds: { log?, network?, memory?, disk? }, windowSeconds? }` or legacy arrays. Saved to History. |
| `POST` | `/api/analyze/correlate/demo` | Demo case |
| `GET`  | `/api/analyze/correlate/:id` | Saved (compact) envelope |
| `GET`  | `/api/analyze/correlate/envelope/:id` | Full `correlation_agent_output.json` |
| `GET`  | `/api/analyze/correlate/report/:id?format=json\|markdown\|pdf` | Report |
| `GET`  | `/api/analyze/correlate/rules` | Rule pack |

`PYTHON_BIN` and `CORRELATION_CASES_DIR` (default `backend/correlation_cases`)
configure it.

**AutoGen.** `register(assistant, executor)` registers `correlate_findings`.
`build_assistant(llm_config)` returns a ready `AssistantAgent`. The tool never
raises: failures come back as an error record that tells the model it is *not*
a "no correlations" result.

---

## 6. Limitations it states about itself

- Each domain not supplied, and each rule that therefore did not run.
- An INVALID memory envelope, and the first memory-agent limitations verbatim.
- Unknown memory clock skew. Syslog timestamps whose year and zone were inferred.
- Network findings carry no timestamps and are one-per-type-and-address, so
  there are no flows, ports or packet times to correlate on.
- Disk findings carry no MAC times.
- **It cannot verify that every source is from the same host and window.** It
  assumes so, and the UI tells the analyst to choose runs accordingly.

---

## 7. Demo case and tests

`python -m correlation_agent demo` correlates the memory agent's own replay of
`memory_agent/tests/fixtures/windows_case` with captured log, network and disk
agent output for the same incident (`tests/fixtures/demo_case/`). It includes
look-alikes the rules must survive: `mimikatz.exe` exists only on disk and stays
unlinked, and Chrome → Google ranks last (its memory finding has source
confidence 0.25).

```bash
python -m unittest discover -s correlation_agent/tests -t .
```

The tests cover:

- helpers: path canonicalisation, address scopes, UTC normalisation that never invents a time;
- every rule's linking and arithmetic, the 0.95 cap, and path + name merging;
- weak links, the private-address penalty, and the low-confidence-input penalty;
- temporal corroboration, clock-skew removal, and no invented timestamps;
- INVALID memory carried through; missing domains reported as not evaluated; rule isolation;
- the demo end to end through `memory_agent`, schema validity, the digest, and compaction;
- envelope-path following and fallback; reproducing a run from its workspace `input.json`;
- the CLI (stdin, structured errors, exit codes, `validate`) and the adapter (never raises, registration, LLM summary).
