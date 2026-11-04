"""Static risk leads (FR-1.5): binaries that import dangerous sinks.

These are HEURISTIC leads for the taint stage -- an import is not a vulnerability.
`taint_angr.py` is where leads get upgraded to probable/confirmed.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from .schema import BinaryAudit, Category, Confidence, Finding, Risk

# sink -> (CWE, category, risk)
SINKS: Dict[str, Tuple[str, Category, Risk]] = {
    "gets": ("CWE-120", Category.MEMORY_CORRUPTION, Risk.HIGH),
    "strcpy": ("CWE-120", Category.MEMORY_CORRUPTION, Risk.MEDIUM),
    "strcat": ("CWE-120", Category.MEMORY_CORRUPTION, Risk.MEDIUM),
    "sprintf": ("CWE-120", Category.MEMORY_CORRUPTION, Risk.MEDIUM),
    "vsprintf": ("CWE-120", Category.MEMORY_CORRUPTION, Risk.MEDIUM),
    "memcpy": ("CWE-787", Category.MEMORY_CORRUPTION, Risk.LOW),
    "system": ("CWE-78", Category.COMMAND_INJECTION, Risk.MEDIUM),
    "popen": ("CWE-78", Category.COMMAND_INJECTION, Risk.MEDIUM),
}
# Network-facing daemons matter more.
SERVICE_HINTS = ("httpd", "uhttpd", "lighttpd", "boa", "goahead", "upnpd", "miniupnpd", "mosquitto", "telnetd", "cgi")


def find_sink_leads(audits: List[BinaryAudit], firmware_id: str) -> List[Finding]:
    out: List[Finding] = []
    for a in audits:
        if a.is_shared_object:
            continue
        hits = [s for s in a.imports if s in SINKS]
        is_service = any(h in a.path.lower() for h in SERVICE_HINTS)
        for sink in hits:
            cwe, cat, risk = SINKS[sink]
            if is_service and risk == Risk.MEDIUM:
                risk = Risk.HIGH
            mitig = []
            if not a.stack_canary:
                mitig.append("no stack canary")
            if not a.nx:
                mitig.append("NX disabled")
            out.append(Finding(
                firmware_id=firmware_id, binary=a.path, architecture=a.architecture,
                category=cat, cwe=cwe, sink=sink, risk_rating=risk,
                confidence=Confidence.HEURISTIC, evidence_ref=f"import:{sink}",
                description=f"Imports `{sink}`" + (f" ({', '.join(mitig)})" if mitig else "") +
                            "; candidate for taint analysis.",
            ))
        # one finding per binary for missing mitigations on service binaries
        if is_service and (not a.nx or not a.stack_canary):
            out.append(Finding(
                firmware_id=firmware_id, binary=a.path, architecture=a.architecture,
                category=Category.MISSING_MITIGATION, cwe="CWE-693", risk_rating=Risk.MEDIUM,
                confidence=Confidence.CONFIRMED, evidence_ref="audit:mitigation_matrix",
                description=f"Network-facing binary lacks hardening (nx={a.nx}, canary={a.stack_canary}, relro={a.relro}).",
            ))
    return out
