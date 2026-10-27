# Memory Analysis Agent

A modular, evidence-integrity-first memory dump analysis agent for the AI-based
multi-agent digital forensics framework.

**Current build: Phases 1–6 complete.** Evidence sealing, Volatility 3
execution, normalisation, a 17-rule deterministic detection pack, timeline
reconstruction, IOC extraction, the validated output envelope, and the AutoGen
adapter.

Runs on a bare Python 3.10+ install with **zero third-party dependencies**.
Volatility 3 is needed only to analyse a real memory image — the analytical half
of the pipeline runs against captured plugin output with `replay`, so rules can
be developed and demonstrated on any machine.

This package is entirely self-contained. It does not import, modify, or depend
on the Node.js backend in `backend/` or the React frontend in `Digital/`.

---

## Architecture

Three strictly separated tiers (full rationale in [`docs/DESIGN.md`](docs/DESIGN.md)):

```
   memory dump ──▶ TIER 1  acquisition & execution   seal, identify OS, run Volatility
   (read-only)              │ raw plugin rows
                            ▼
                    TIER 2  normalisation            rows → OBSERVATIONS (judgement-free)
                            │ observations
                            ▼
                    TIER 3  detection & synthesis    rules → FINDINGS, timeline, IOCs
                            │
                            ▼
                    memory_agent_output.json ──▶ Correlation Agent
```

**Tier 1 never interprets. Tier 3 never touches the dump.**

Every finding traces backward through `obs_id` → `{plugin, row_index, physical offset}`
→ the dump itself. No conclusion is orphaned from its evidence.

---

## Install

```bash
python --version          # 3.10 or later
git clone -b memory_agent https://github.com/ASHMITHA16/forensic.git
cd forensic
```

That is the whole installation for Phase 1. There is nothing to `pip install`.

Run the test suite to confirm:

```bash
python -m unittest discover -s memory_agent/tests -t .
```

Expected: `Ran 79 tests ... OK`

---

## Usage

### Seal evidence and produce a chain-of-custody record

```bash
python -m memory_agent verify /path/to/dump.raw \
    --case-id DF-2026-001 \
    --investigator "Bhoomi R K" \
    --acquisition-tool WinPmem \
    --acquired-utc 2026-04-12T02:00:00Z \
    -o ./memory_agent_cases
```

Output:

```
========================================================================
  MEMORY EVIDENCE SEAL / CHAIN OF CUSTODY
========================================================================
  Case ID        : DF-2026-001
  Investigator   : Bhoomi R K
  Run ID         : ecb1098c-3b68-43d1-ac11-66475ee4e1ab
  Evidence ID    : EV-MEM-133AD5B1
------------------------------------------------------------------------
  File           : win10_ws01.raw
  Size           : 11.4 MiB  (12,000,000 bytes)
------------------------------------------------------------------------
  SHA-256        : 9c7ab277f6d05515602ca6bffb96644e09436a57c57d597a03756014...
  MD5            : 9d621c41108f24e558d3800153f62bee   (cross-check only)
------------------------------------------------------------------------
  Integrity      : VERIFIED
  Method         : seal only (use --paranoid to re-read the dump)
  Identity check : performed
  Read-only      : enforced (O_RDONLY, no write mode used)
------------------------------------------------------------------------
  Audit entries  : 9
  Audit SHA-256  : a67d0142ebab451556b58e2634d1857c8bdcf84fcc5136d1d094a8dd...
========================================================================
```

Add `--json` to emit the machine-readable custody record instead, and `-q` to
suppress output entirely (exit code still signals the result).

### Verify an audit trail has not been altered

```bash
python -m memory_agent audit-verify ./memory_agent_cases/DF-2026-001/<run-id>/audit.jsonl
```

It locates the anchor in the sibling `custody.json` automatically. If anything
in the trail was modified in place, it reports the exact sequence number at which
the hash chain breaks:

```
  Chain          : *** BROKEN ***
  Broken at seq  : 5
  Reason         : hash chain broken: entry does not link to its predecessor

  Entries before this sequence number remain provably intact.
  This entry and everything after it must be treated as suspect.
```

If the whole trail was rewritten and re-linked — which the chain alone cannot
see — the anchor catches it:

```
  Chain links    : consistent
  Completeness   : complete (opens and closes correctly)
  External anchor: *** MISMATCH ***
                   ! final chain hash does not match the recorded anchor:
                     the trail was rewritten in full
```

### Run a full analysis

```bash
python -m memory_agent analyze /evidence/memdump.raw \
    --case-id DF-2026-001 \
    --investigator "A. Analyst" \
    --acquired-utc 2026-04-12T02:25:00Z \
    -o /cases
```

Seals the evidence, identifies the OS, runs the plugin plan, normalises the
output, evaluates the rule pack, builds the timeline, extracts indicators,
re-verifies the evidence, and writes a validated envelope.

| Flag | Effect |
|---|---|
| `--deep` | also run `handles`, `filescan`, `mutantscan`, `registry.hivelist`. Substantially slower. |
| `--timeout N` | base per-plugin budget; each plugin scales it by its own cost factor |
| `--vol PATH` | Volatility executable, if it is not on `PATH` |
| `--only P1 P2` | run only these plugins. Coverage drops accordingly, and the envelope names the rules that lost their input. |
| `--allowlist-vendor` | drop Microsoft and cloud ranges from the IOC list. Off by default: C2 is routinely hosted there. |
| `--json` | write the envelope to stdout |

Supplying `--acquired-utc` is what makes `clock_skew_seconds` computable. Without
it the field stays `null` — an unknown skew is reported as unknown rather than
assumed to be zero.

### Analyse without a memory image

```bash
python -m memory_agent replay memory_agent/tests/fixtures/windows_case \
    --case-id DF-DEMO-001
```

Runs stages S4–S8 against captured plugin output — the bundled fixture corpus, or
the `raw/` directory of any previous run. No Volatility, no dump.

### List the rule pack

```bash
python -m memory_agent rules          # or --json
```

Every rule with its version, severity, base confidence and ATT&CK mapping. A
reviewer is entitled to disagree with a threshold and cannot do so without
seeing it.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Operational error (bad path, unwritable workspace, no Volatility) |
| `2` | **Integrity failure** — evidence or audit trail did not verify |
| `3` | Not implemented for this input (e.g. a non-Windows image) |

Machine-readable, so the CLI can be driven from a script or another process
without parsing prose.

---

## Case workspace layout

Each run creates an isolated directory. The agent **never writes beside the
evidence** — `create_workspace()` refuses a workspace inside the evidence's own
directory, and warns when the workspace merely shares a volume with it.

The check compares filesystem **identity** (`st_dev`, `st_ino`) of the nearest
existing ancestor, not resolved path strings. String comparison is not enough:
on case-insensitive filesystems (NTFS, APFS) `/Evidence` and `/EVIDENCE` are the
same directory but different strings, `Path.resolve()` in non-strict mode gives
up canonicalising when it hits an access error and splices the as-typed tail back
on, and symlinks or junctions can alias one directory under many names. Identity
is immune to all three.

```
memory_agent_cases/<case_id>/<run_id>/
├── audit.jsonl                 tamper-evident hash-chained action log
├── custody.json                chain-of-custody record
├── raw/                        verbatim Volatility output, per plugin
├── cache/                      Volatility scan cache and temp files
├── artifacts/                  dumped regions
└── memory_agent_output.json    the validated output envelope
```

---

## Evidence integrity model

**1. Pre-analysis seal.** SHA-256 and MD5 computed in a single streaming pass
(8 MiB chunks, so a 16 GB dump never lands in memory), plus size, inode, device
and timestamps.

MD5 is recorded only for cross-checking against legacy tools that still report
it. It is collision-broken and is never relied on alone.

The file is stat'ed **both before and after** the hashing pass. If it changed in
between — an acquisition tool still writing, a share being updated — the
resulting `(size, digest)` pair describes an indeterminate byte range that
*nobody can reproduce*. That is recorded as `stable_during_hash: false` with a
prominent warning rather than being emitted as though it were authoritative.

**2. Read-only access.** Every read goes through `open_readonly`, which uses
`os.open(path, os.O_RDONLY)` — the intent is expressed at the syscall boundary
and is auditable by reading the code. No write mode is used anywhere in the
package.

**3. Post-analysis verification.** Recompute and re-stat, then compare.

The report keeps two lists deliberately apart:

- `discrepancies` — findings that **invalidate** the run: the digest changed,
  the size changed, or the inode/device changed (the path now points at a
  different file object).
- `metadata_notes` — informational drift that does **not** invalidate: an mtime
  touch with an identical digest means the bytes are intact and something merely
  touched the file.

They are separate because a caller checking `len(discrepancies) > 0` is making
the obvious reading of the field name, and that reading must not raise a false
tamper alarm on every ordinary run.

**Inode caveat.** `st_ino` is `0` on FAT/exFAT removable media, on some network
shares, and on Windows when the file cannot be opened to query its NTFS index.
Zero means *unknown*, not an identity — comparing it would either pass vacuously
or invalidate an intact dump. Where it is unavailable the check is skipped and
`inode_check: "unavailable on this filesystem"` is recorded, so the custody
record never asserts an identity that was never established.

By default `verify` does not re-read the dump after sealing: nothing happens in
between, so a second full pass over 32 GB costs minutes to prove that two
seconds changed nothing. The report says `verification_method: "seal_only"`.
Pass `--paranoid` to force the re-read.

`analyze` is different: the re-read is **mandatory** there and not configurable.
An external tool has just been pointed at the evidence twenty times, and
confirming the file is byte-identical afterwards is the entire basis for
claiming the analysis did not alter it.

**4. Hash-chained audit trail.** Every action appends one JSON line embedding
the SHA-256 of the previous line:

```
entry[0].prev_hash = "000...0"           (genesis)
entry[n].prev_hash = sha256(line[n-1])
```

The chain's real value is **localisation**: verification reports the exact
sequence number at which the record diverges, so entries before it stay provably
intact while everything after is provably suspect.

**What the chain alone cannot do.** A hash chain with no key has no secret.
Anyone who can write `audit.jsonl` can renumber every entry, recompute every
link, and produce a file that verifies perfectly. Nothing inside the file can
prevent that.

What defeats a full rewrite is an anchor held *outside* the trail:
`final_chain_hash` and `log_sha256`, computed at seal time and written into
`custody.json`. `audit-verify` finds that anchor automatically and reports **two
distinct verdicts**:

| | Means |
|---|---|
| `Chain links: consistent` | No entry was edited, deleted, inserted or reordered *in place* |
| `Completeness: complete` | Opens with `audit.open`, ends with `audit.close`, and the count declared in the closing entry matches — this is what catches truncation and post-seal appending, neither of which breaks the links |
| `External anchor: VERIFIED` | It also matches a known-good anchor. **Only this is proof against a determined attacker.** |

With `--no-anchor`, or when no `custody.json` is found, the tool says
`External anchor: NOT CHECKED` and states plainly that internal consistency is
not proof the trail was never rewritten. Printing "INTACT" on the strength of
the links alone would be exactly the kind of overclaim this agent exists to
avoid.

In a real deployment the anchor would also be recorded somewhere the analysis
host cannot reach.

### What this does not claim

Software cannot make a file physically immutable. The guarantee here is
narrower and deliberately honest: **the agent never opens evidence for writing,
and any modification by anything is detected and reported.** Genuine
write-protection is the job of a hardware write blocker or a read-only mount.
The custody record states this in a `read_only_note` field rather than
overclaiming — overclaiming is how findings get excluded.

Reading the evidence also updates its **access time** on a default-mounted
volume, so the agent does touch evidence metadata even though it never touches
the bytes. `O_NOATIME` is requested where the platform supports it and the
caller owns the file; where it is unavailable, `st_atime_ns` is recorded in the
seal so the change is on the record rather than silently denied.

Standard practice remains to work from a forensic copy and leave the original
untouched.

---

## Observation vs interpretation

This is the property the whole design exists to deliver, so it is worth being
precise about the mechanism rather than just claiming it.

**Tier 2 records facts.** An observation may not contain a judgement. There is no
`suspicious` field, no `severity`, no `confidence`. `ldrmodules` reporting a
module missing from all three PEB lists produces three booleans — not a field
called `hidden`. The schema *enforces* this: `validate_observation` rejects any
observation carrying a verdict field, and a test asserts no extractor emits one.

**Tier 3 interprets, and shows its working.** Every finding carries four
separate fields:

```jsonc
"observation_statement": "The VAD at 0x2a0000 in PID 2456 is private, is marked
                          PAGE_EXECUTE_READWRITE, and its first bytes are 4d 5a.",
"interpretation":        "Consistent with reflective PE injection.",
"alternative_explanations": [
    "Just-in-time compilation. .NET, JavaScript and JVM engines allocate exactly
     this kind of region during normal execution, and this is by a wide margin
     the most common cause.",
    "A legitimate packed or self-extracting application." ],
"analyst_action":        "Dump the region and examine it statically."
```

`alternative_explanations` may not be empty — that is a schema violation, not a
stylistic lapse. The field exists so a downstream LLM cannot treat a rule hit as
settled fact, and a rule author who cannot name a benign cause has not finished
thinking about the rule.

**Confidence is arithmetic.**

```
confidence = clamp(base_confidence + Σ adjustments, 0.0, 0.95)
```

Every term appears in `confidence_basis` in plain text, including the
corroboration bonuses added after all rules have run. The 0.95 ceiling is a
design commitment: this agent examines one evidence domain and never asserts
certainty.

## Absence is never silent

The most dangerous output a memory forensics tool can produce is a confident
empty findings list on a compromised machine. Three mechanisms prevent it.

**Tri-state cross-view.** `cross_view.pslist` is `false` only when `pslist` ran
and did not return the process; it is `null` when `pslist` did not run. Rules
test `is False`, never falsy. Without this, a `pslist` timeout would manufacture
a CRITICAL hidden-process finding on a healthy machine.

**Rules report `not_evaluated`.** When a plugin a rule depends on fails, the rule
is not run and is recorded with the reason, and `limitations` says so in as many
words: *"MEM-I-001 was NOT evaluated because windows.malfind (timeout). Absence
of this finding type is therefore not evidence of its absence on the system."*

**Rule isolation.** A rule that raises is recorded as errored; the other sixteen
still run. Losing sixteen findings to one unexpected `None` would be a failure at
the thing the tool exists to do.

## The timeline is honest about what it knows

A memory image yields very few real timestamps. Every event declares its
`precision`:

| Precision | Meaning | `timestamp_utc` |
|---|---|---|
| `exact` | read from the artifact itself | present |
| `approximate` | derived from a related artifact, bounded and explained | present |
| `relative` | no timestamp; ordering inferred | **null** |
| `unknown` | present in the image, not placeable in time | **null** |

`relative` and `unknown` events carry a null timestamp and the schema enforces
it. Rendering an inferred ordering as a time is exactly the confusion the
precision field exists to prevent — and it is how a correlation agent ends up
interleaving an invented memory timestamp with a real MFT timestamp and
reporting a sequence of events that never happened.

## Reproducibility, scoped honestly

"Same dump ⇒ byte-identical output" is false as stated: the envelope carries a
run id, wall-clock timestamps and durations. The claim that *is* true, and is
checked by `tests/test_pipeline.py`:

```python
from memory_agent.report import core_digest
core_digest(run_a) == core_digest(run_b)   # same evidence, same rule pack
```

`report.deterministic_core` strips everything that legitimately varies and
returns the analysis itself — observations, findings, timeline, indicators,
coverage, limitations. Identifiers are allocated from sorted order, so two runs
over the same input produce the same `obs_id`s and the two envelopes can simply
be diffed.

---

## Running a full analysis

### Install Volatility 3

Current release is **2.28.0** (April 2026), requires Python 3.8+.

```bash
pip install volatility3
vol --help
```

On Windows, if `vol` is not on `PATH` after installing:

```powershell
py -m pip install volatility3
py -m volatility3 --help
```

Confirm it can read a dump:

```bash
vol -f /path/to/dump.raw windows.info
```

Windows symbol tables are downloaded automatically from Microsoft's symbol
server on first use, so no manual symbol setup is needed for Windows dumps.
The first run against a new kernel build therefore needs internet access and
spends a minute or two in `windows.info` converting the PDB; the result is
cached under `volatility3/symbols/windows/` and later runs skip it.
Linux dumps require an ISF file matching the exact kernel build — the usual
place demos fail, which is why Phase 1 targets Windows first.

The agent locates `vol` by trying, in order: `--vol <path>`, the `VOLATILITY_BIN`
environment variable, `vol` / `vol.py` / `volatility3` on `PATH`, and finally
`python -m volatility3.cli`. It confirms the executable identifies itself as
Volatility 3 before running anything, and records the version in the envelope —
running plugins against an unidentified binary and reporting the results as
forensic findings would not be defensible.

### Get a test memory dump

Two good free sources:

- **[Volatility Foundation Memory Samples](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)** —
  the canonical list. `cridex.vmem` (~malware, small) and `zeus.vmem` are good
  first targets: small enough to iterate quickly, and they contain real
  malicious activity so the detection rules have something to find.
- **[MemLabs](https://github.com/stuxnet999/MemLabs)** — CTF-style Windows
  dumps with published solutions, useful for checking the agent finds what it
  should.

Older XP/Win7 samples still work with Volatility 3 and are far quicker to
iterate on than a modern 16 GB Windows 11 dump.

For a modern target, **[DFIR Madness case001, "The Stolen Szechuan
Sauce"](https://dfirmadness.com/the-stolen-szechuan-sauce/)** ships a 2 GB
Windows 10 desktop image (`DESKTOP-SDN1RPT-memory.zip`, MD5
`CF31E2635C77811AAA1BB04A92A721E2`) with a published answer key. The agent
completes it in about nine minutes with every plugin and rule evaluated, and
ranks the injected `spoolsv.exe` (PID 2188) first.

### From the web UI

The Node backend (`backend/agents/memoryAgent.js`) runs this package as a
child process and the Memory Agent page polls it as a background job, so a
multi-hour analysis is not cut off by an HTTP timeout. The page shows the
current stage and plugin as the agent records them in `audit.jsonl`.

| Variable | Default | Effect |
|---|---|---|
| `PYTHON_BIN` | `python` | Interpreter used to run `python -m memory_agent` |
| `VOLATILITY_BIN` | `vol` on `PATH` | Volatility 3 executable, read by the agent itself |
| `MEMORY_CASES_DIR` | `backend/memory_cases` | Where case workspaces are written |
| `MEMORY_PLUGIN_TIMEOUT_S` | agent default (300) | Base per-plugin budget; raise it for very large images |
| `MAX_UPLOAD_BYTES` | 32 GB | Upload ceiling for dumps and disk images |

The full envelope stays in the case workspace and can be downloaded from the
results page; the page itself shows the findings, the first 300 IOCs and up to
500 timestamped timeline events.

### Test without any dump at all

Tiers 2 and 3 consume JSON, not memory images:

```bash
python -m memory_agent replay memory_agent/tests/fixtures/windows_case \
    --case-id DF-DEMO-001
```

That runs normalisation, all 17 rules, the timeline and IOC extraction against a
bundled fixture corpus, and writes a complete envelope. The corpus is a synthetic
Windows incident built to trigger every rule in the pack *and* to include the
benign look-alikes each rule has to survive — a JIT region in Chrome beside an
injected region in a dropper, an HTTPS connection beside a connection to port
4444.

A replayed envelope is always stamped `INVALID`. No evidence was sealed, so
nothing in it is admissible; that is the correct status, not a malfunction.

The same command works on the `raw/` directory of any previous real run, which
is how a finished case can be re-analysed under a newer rule pack without
touching the evidence again.

---

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| **1** | Evidence integrity, audit trail, workspace, CLI | **complete** |
| **2** | Volatility 3 runner, OS identification, plugin planner | **complete** |
| **3** | Extractors → normalised observations, schema contract | **complete** |
| **4** | Detection rule engine (rule pack v1, 17 rules) | **complete** |
| **5** | Timeline, IOC extraction, full output envelope | **complete** |
| **6** | AutoGen adapter, fixture corpus, 301 tests | **complete** |

### Not covered by this build

- **Linux and macOS images.** The planner has a Linux plugin plan and will
  execute it, retaining the raw output, but there are no Linux extractors: no
  observations, findings, timeline or IOCs are derived. The envelope says so
  rather than emitting an empty analysis. macOS is refused outright.
- **Registry, handle and file-object analysis.** Available behind `--deep`, but
  no rules consume them yet.
- **Anything requiring the disk.** Every rule reasons from memory alone. Where a
  question needs the filesystem or the registry hive on disk, the finding's
  `analyst_action` says so.

---

## Module map

```
memory_agent/
├── core/
│   ├── errors.py       exception hierarchy with stable machine-readable codes
│   ├── evidence.py     hashing, read-only access, sealing, chain of custody
│   ├── audit.py        hash-chained tamper-evident JSONL trail
│   ├── workspace.py    isolated per-run case workspace
│   ├── rows.py         tolerant readers for Volatility's unstable column names
│   ├── runner.py       Volatility 3 subprocess wrapper, timeouts, capture
│   ├── profile.py      OS identification cascade, clock anchoring
│   ├── planner.py      OS → plugin plan, with the rules each plugin feeds
│   └── schema.py       THE CONTRACT — records and validation, zero-dependency
├── extractors/         TIER 2  rows → judgement-free observations
│   ├── base.py         shared machinery, tri-state plugin availability
│   ├── processes.py  network.py  commands.py
│   └── modules.py    injection.py  services.py
├── detectors/          TIER 3  observations → findings
│   ├── engine.py       rule runner, isolation, confidence arithmetic
│   └── rules/          process, injection, network, command, module, service
├── synthesis/
│   ├── timeline.py     precision-labelled events
│   └── iocs.py         extraction, allowlisting, dedup, defanging
├── report.py           envelope assembly, validation, deterministic core
├── verify.py           the sealing pipeline (Phase 1)
├── analyze.py          the full pipeline, S0–S8, plus replay
├── autogen_adapter.py  the only file that knows AutoGen exists
├── cli.py              command-line interface
├── tests/              301 tests, stdlib unittest, no dependencies
│   └── fixtures/       captured plugin output for a synthetic Windows case
└── docs/DESIGN.md      approved architecture and output contracts
```
