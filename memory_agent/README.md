# Memory Analysis Agent

A modular, evidence-integrity-first memory dump analysis agent for the AI-based
multi-agent digital forensics framework.

**Current build: Phase 1 — evidence sealing and chain of custody.**
Runs on a bare Python 3.10+ install with **zero third-party dependencies** and
**no forensic toolchain required**.

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

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Operational error (bad path, unwritable workspace) |
| `2` | **Integrity failure** — evidence or audit trail did not verify |
| `3` | Not implemented in this phase |

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
├── raw/                        verbatim Volatility output      (Phase 2+)
├── cache/                      Volatility scan cache           (Phase 2+)
├── artifacts/                  dumped regions                  (Phase 4+)
└── memory_agent_output.json    final envelope                  (Phase 5+)
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
Pass `--paranoid` to force the re-read. From Phase 2, where plugins run in
between, the re-read becomes mandatory.

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

## Preparing for Phase 2

Phase 2 adds the Volatility 3 runner, OS identification, and the plugin planner.
Installing the toolchain now means Phase 2 is runnable the moment it lands.

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
Linux dumps require an ISF file matching the exact kernel build — the usual
place demos fail, which is why Phase 1 targets Windows first.

The agent will locate `vol` via a configurable path rather than a hardcoded one,
so it works on any machine.

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

### Test without any dump at all

Tiers 2 and 3 consume JSON, not memory images. From Phase 3 onward the
detection rules are unit-tested against fixture observation files, so rule
development is never blocked on having a dump or a working Volatility install.

---

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| **1** | Evidence integrity, audit trail, workspace, CLI | **complete** |
| 2 | Volatility 3 runner, OS identification, plugin planner | next |
| 3 | Extractors → normalised observations | |
| 4 | Detection rule engine (rule pack v1, 17 rules) | |
| 5 | Timeline, IOC extraction, full output envelope | |
| 6 | AutoGen adapter, fixture corpus | |

---

## Module map

```
memory_agent/
├── core/
│   ├── errors.py       exception hierarchy with stable machine-readable codes
│   ├── evidence.py     hashing, read-only access, sealing, chain of custody
│   ├── audit.py        hash-chained tamper-evident JSONL trail
│   └── workspace.py    isolated per-run case workspace
├── verify.py           Phase 1 pipeline
├── cli.py              command-line interface
├── tests/              79 tests, stdlib unittest, no dependencies
└── docs/DESIGN.md      approved architecture and output contracts
```
