"""
correlation_agent.linking  (stage C2)
─────────────────────────────────────────────────────────────────────
Entities that appear in more than one evidence domain.

Every link carries a *strength*, because a shared value is only as
meaningful as it is rare:

  strong    public IPv4, domain, full file path
  moderate  private IPv4, program image, non-executable file name, user
  weak      names present on every host (svchost, lsass, root, ...) and
            hostnames -- reported, never correlated on alone
"""

from __future__ import annotations

from typing import Any, Iterable

from .core.constants import COMMON_IMAGES, COMMON_USERS, DOMAINS, STRENGTH_RANK
from .core.entities import EXECUTABLE_EXT, ip_scope


def link_keys(item: dict[str, Any]) -> list[dict[str, Any]]:
    """Every linkable key an evidence item exposes, with its strength."""
    e = item["entities"]
    keys: list[dict[str, Any]] = []
    for ip in e["ips"]:
        scope = ip_scope(ip)
        if scope == "public":
            keys.append({"key": f"ip:{ip}", "type": "ip", "value": ip, "strength": "strong", "scope": scope})
        elif scope == "private":
            keys.append({"key": f"ip:{ip}", "type": "ip", "value": ip, "strength": "moderate", "scope": scope})
        # loopback, link-local, multicast, broadcast, unspecified: never linked
    for d in e["domains"]:
        keys.append({"key": f"domain:{d}", "type": "domain", "value": d, "strength": "strong"})
    for p in e["paths"]:
        keys.append({"key": f"path:{p}", "type": "path", "value": p, "strength": "strong"})
    for img in e["images"]:
        keys.append({"key": f"image:{img}", "type": "image", "value": img,
                     "strength": "weak" if img in COMMON_IMAGES else "moderate"})
    for f in e["files"]:
        if not EXECUTABLE_EXT.search(f):
            keys.append({"key": f"file:{f}", "type": "file", "value": f, "strength": "moderate"})
    for u in e["users"]:
        keys.append({"key": f"user:{u}", "type": "user", "value": u,
                     "strength": "weak" if u in COMMON_USERS else "moderate"})
    for h in e["hosts"]:
        keys.append({"key": f"host:{h}", "type": "host", "value": h, "strength": "weak"})
    return keys


def build_entity_index(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cross-domain links only, sorted strongest and widest first."""
    index: dict[str, dict[str, Any]] = {}
    for item in items:
        for k in link_keys(item):
            entry = index.setdefault(k["key"], {**k, "refs": set(), "domains": set()})
            entry["refs"].add(item["ref"])
            entry["domains"].add(item["domain"])

    links = [
        {
            "key": e["key"], "type": e["type"], "value": e["value"], "strength": e["strength"],
            "scope": e.get("scope"),
            "domains": [d for d in DOMAINS if d in e["domains"]],
            "evidence_refs": sorted(e["refs"]),
        }
        for e in index.values()
        if len(e["domains"]) >= 2
    ]
    links.sort(key=lambda l: (-STRENGTH_RANK[l["strength"]], -len(l["domains"]), l["key"]))
    return links
