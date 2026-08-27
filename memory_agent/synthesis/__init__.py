"""
memory_agent.synthesis
─────────────────────────────────────────────────────────────────────
Timeline reconstruction and indicator extraction.

Both are pure functions over observations and findings. Neither reads
the memory image, and neither introduces a fact that is not already
present in a cited observation.
"""

from __future__ import annotations

from .iocs import defang, extract_iocs, render_defanged
from .timeline import PRECISION_CONFIDENCE, build_timeline, timeline_summary

__all__ = [
    "build_timeline", "timeline_summary", "PRECISION_CONFIDENCE",
    "extract_iocs", "defang", "render_defanged",
]
