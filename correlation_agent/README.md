# Correlation & Reasoning Agent

The downstream agent of the multi-agent digital forensics framework. It takes
the outputs of the **log, network, memory and disk** agents and works out which
findings describe the same activity. The result is an evidence-cited set of
correlations, an ATT&CK attack chain, and two competing hypotheses.

Runs on a bare Python 3.10+ install with **zero third-party dependencies** and
**no LLM**, the same as `memory_agent`. AutoGen is reached only through
`autogen_adapter.py`. Full design: [`docs/DESIGN.md`](docs/DESIGN.md).

```
log / network / memory / disk findings
   │
   ▼  C1 normalise → C2 link → C3 correlate (COR-v1) → C4 timeline → C5 reason → C6 assess
   │
   ▼
correlation_agent_output.json   (+ the exact input.json, for reproduction)
```

## Usage

From the repository root:

```bash
python -m correlation_agent demo                       # bundled case, not evidence
python -m correlation_agent correlate --input case.json -o ./correlation_cases
python -m correlation_agent correlate --input - --json < case.json
python -m correlation_agent rules                      # every rule, base and scope
python -m correlation_agent validate <correlation_agent_output.json>
```

A minimal `case.json`:

```json
{
  "memory":  { "envelope_path": "backend/memory_cases/DF-…/<run>/memory_agent_output.json" },
  "network": { "findings": [ { "type": "Beaconing Activity", "ip": "185.77.22.90", "detail": "412 packets" } ] }
}
```

Exit codes: `0` success, `1` bad input / operational error, `2` contract
violation. With `--json`, errors print as `{"error_code": "CA-E-…", "message": …}`.

## What makes the output defensible

- **Facts and hypotheses are separate fields.** Each correlation has
  `observation_statement` (citing evidence refs, which cite the source finding),
  `interpretation`, `alternative_explanations` (never empty) and `analyst_action`.
- **Confidence is arithmetic**, capped at 0.95, with every term in `confidence_basis`.
- **Weak links never correlate.** Names found on every host (`svchost`, `root`)
  are reported but cannot create a correlation alone.
- **Absence is never silent.** A domain not supplied makes its rules
  `not_evaluated`, and `limitations` says so.
- **Nothing is timed that wasn't.** The timeline holds only real timestamps, and
  untimed findings are counted.
- **Non-admissible stays non-admissible.** An INVALID memory envelope marks
  every correlation that cites it.
- **Reproducible.** `core_digest` over the deterministic core. Re-running a
  case's stored `input.json` yields the same digest.

## Tests

```bash
python -m unittest discover -s correlation_agent/tests -t .
```

## Module map

```
correlation_agent/
├── core/
│   ├── constants.py   versions, ATT&CK tables, weights — every threshold in one place
│   ├── entities.py    UTC, IP scope, path canonicalisation, entity extraction
│   ├── errors.py      CA-E-* error codes
│   └── schema.py      THE CONTRACT — hand-validated, zero-dependency
├── normalise.py       C1  findings → evidence items; reads memory_agent_output.json
├── linking.py         C2  cross-domain entities with strength
├── rules.py           C3  rule pack COR-v1
├── engine.py          C3  rule runner, confidence arithmetic, isolation
├── timeline.py        C4  real timestamps only, clock skew removed
├── reasoning.py       C5  ATT&CK chain, H1 vs H0
├── assess.py          C6  risk, confidence, limitations
├── correlate.py       pipeline + input contract + demo payload
├── report.py          digest, compaction, workspace, summary
├── cli.py             command-line interface
├── autogen_adapter.py the only file that knows AutoGen exists
├── tests/             stdlib unittest; fixtures/demo_case
└── docs/DESIGN.md
```

The Node backend calls this package through `backend/agents/correlationAgent.js`.
