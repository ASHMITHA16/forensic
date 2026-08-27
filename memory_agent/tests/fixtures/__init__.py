"""
Fixture corpus and loader.

The corpus is captured Volatility 3 JSON for a synthetic Windows
incident. It exists so that Tiers 2 and 3 -- normalisation, detection,
timeline and IOC extraction, which is the great majority of the
analytical code -- can be developed, tested and demonstrated on any
machine, with no memory image and no Volatility install.

The scenario planted in ``windows_case`` is designed to exercise every
rule in pack v1, and to include the benign look-alikes each rule has to
survive: a JIT region in Chrome next to an injected region in a dropper,
an exited process that legitimately lost its parent next to one that did
not, an HTTPS connection next to a connection to port 4444.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURE_ROOT = Path(__file__).resolve().parent
WINDOWS_CASE = FIXTURE_ROOT / "windows_case"


def load_rows(plugin: str, case: Path | None = None) -> list[dict[str, Any]]:
    """Rows for one plugin, treegrid-flattened exactly as the runner does."""
    from ...core.runner import flatten_treegrid

    path = (case or WINDOWS_CASE) / f"{plugin}.json"
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return flatten_treegrid(data if isinstance(data, list) else [])


def load_results(case: Path | None = None) -> dict[str, Any]:
    """Every fixture in a case, as ``PluginResult`` objects."""
    from ...core.runner import load_raw_results

    return load_raw_results(case or WINDOWS_CASE)
