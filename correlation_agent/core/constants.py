"""
correlation_agent.core.constants
─────────────────────────────────────────────────────────────────────
Versions, domains and the reference tables every stage reads.

Kept in one place so that a reviewer can see every threshold and every
mapping the agent relies on without reading the code that applies them.
"""

from __future__ import annotations

SCHEMA_VERSION = "1.0.0"
AGENT_NAME = "correlation_agent"
AGENT_VERSION = "1.0.0"
RULE_PACK_VERSION = "COR-v1.0"

DOMAINS = ("log", "network", "memory", "disk")
DOMAIN_PREFIX = {"log": "LOG", "network": "NET", "memory": "MEM", "disk": "DSK"}

# This agent joins evidence from several domains it did not examine itself;
# like the memory agent it never asserts certainty.
CONFIDENCE_CEILING = 0.95
DEFAULT_WINDOW_S = 15 * 60       # "close in time" for corroboration
FAR_APART_S = 24 * 60 * 60       # timestamps this far apart weaken a link

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

STRENGTH_RANK = {"weak": 0, "moderate": 1, "strong": 2}

# The network agent's findings carry no severity; this is how its types read.
NETWORK_TYPE_SEVERITY = {
    "Known Malicious IP": "high",
    "Beaconing Activity": "medium",
    "Potential Port Scan": "medium",
    "External Connection": "low",
}

# ATT&CK techniques for findings whose agent emits none. Items that use
# these are flagged ``mitre_inferred`` so they are distinguishable from
# techniques the source agent asserted itself.
INFERRED_TECHNIQUES = {
    "log": {
        "Failed Login": ["T1110"],
        "Brute Force Activity": ["T1110"],
        "Unauthorized Access": ["T1078"],
        "Privilege Escalation": ["T1068"],
        "Suspicious Command": ["T1059"],
        "Log Tampering": ["T1070.001"],
        "Persistence Indicator": ["T1547"],
        "Malware Indicator": ["T1204"],
    },
    "network": {
        "Potential Port Scan": ["T1046"],
        "Known Malicious IP": ["T1071"],
        "Beaconing Activity": ["T1071"],
    },
    "disk": {
        "Deleted File": ["T1070.004"],
        "Known Attacker Tool": ["T1105"],
        "Suspicious Executable": ["T1105"],
    },
}

# Technique (or parent technique) -> tactic. Covers every technique the four
# agents emit or the table above infers.
TECHNIQUE_TACTIC = {
    "T1595": "Reconnaissance",
    "T1190": "Initial Access", "T1566": "Initial Access",
    "T1059": "Execution", "T1204": "Execution", "T1053": "Execution",
    "T1543": "Persistence", "T1547": "Persistence", "T1574": "Persistence",
    "T1068": "Privilege Escalation",
    "T1055": "Defense Evasion", "T1014": "Defense Evasion", "T1027": "Defense Evasion",
    "T1036": "Defense Evasion", "T1070": "Defense Evasion", "T1218": "Defense Evasion",
    "T1078": "Defense Evasion",
    "T1110": "Credential Access", "T1003": "Credential Access",
    "T1046": "Discovery", "T1082": "Discovery", "T1087": "Discovery", "T1016": "Discovery",
    "T1021": "Lateral Movement",
    "T1071": "Command and Control", "T1105": "Command and Control",
    "T1571": "Command and Control", "T1205": "Command and Control",
    "T1041": "Exfiltration", "T1048": "Exfiltration",
    "T1486": "Impact",
}

TACTIC_ORDER = (
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
)

# Present on every Windows/Linux host. A match on one of these alone says
# nothing about shared activity, so it is recorded as a weak link only.
COMMON_IMAGES = frozenset({
    "system", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "svchost",
    "explorer", "conhost", "dllhost", "taskhostw", "runtimebroker", "searchindexer",
    "spoolsv", "chrome", "firefox", "msedge", "iexplore", "sshd", "systemd", "kernel",
    "cron", "sudo", "bash", "sh", "init",
})
COMMON_USERS = frozenset({"system", "root", "administrator", "admin", "guest", "unknown", "localsystem"})

# Risk-score weights (C6)
DOMAIN_SEVERITY_POINTS = {"info": 0, "low": 3, "medium": 8, "high": 14, "critical": 20}
CORRELATION_SEVERITY_POINTS = {"info": 1, "low": 4, "medium": 10, "high": 18, "critical": 25}
