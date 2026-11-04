"""angr taint / sink-reachability stage (FR-3.1 .. FR-3.4)  --  OWNER: Aleena

!! SKELETON, NOT YET TESTED against a real firmware binary. !!
What exists: bounded CFG recovery + "which functions can reach the sink" (a real
reachability lead). What you still need to add (see TODOs): sources (recv/read/
getenv/CGI params), symbolic input, taint propagation, and crash-state capture.

Rules from the PRD: budgets on everything (FR-3.4), report partial results as
`incomplete`, never emit an exploit -- crash_state is registers/offsets/path only.
"""
from __future__ import annotations

from typing import List

from .schema import Arch, Category, Confidence, CrashState, Finding, Risk

CFG_TIMEOUT_S = 120      # wall-clock budget for CFG recovery
SINKS = ("strcpy", "memcpy", "sprintf", "system", "popen")


def analyse_binary(path: str, rel: str, firmware_id: str, arch: Arch) -> List[Finding]:
    try:
        import angr  # heavy import; only needed in the analysis worker
        import networkx as nx
    except ImportError:
        return []

    proj = angr.Project(path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True, timeout=CFG_TIMEOUT_S)   # bounded CFG
    findings: List[Finding] = []

    for sink in SINKS:
        func = next((f for f in cfg.functions.values() if f.name == sink), None)
        if func is None:
            continue
        callgraph = cfg.functions.callgraph
        callers = list(callgraph.predecessors(func.addr))
        for caller_addr in callers[:20]:                       # budget: callers per sink
            caller = cfg.functions.get(caller_addr)
            findings.append(Finding(
                firmware_id=firmware_id, binary=rel, architecture=arch,
                category=Category.COMMAND_INJECTION if sink in ("system", "popen") else Category.MEMORY_CORRUPTION,
                cwe="CWE-78" if sink in ("system", "popen") else "CWE-120",
                address=hex(caller_addr), sink=sink, source=None,
                tainted_path=[hex(caller_addr), hex(func.addr)],
                crash_state=CrashState(),          # TODO(Aleena): fill from a symbolic run
                risk_rating=Risk.MEDIUM, confidence=Confidence.PROBABLE,
                evidence_ref=f"cfg:{caller.name if caller else hex(caller_addr)}->{sink}",
                description=f"`{caller.name if caller else hex(caller_addr)}` calls `{sink}` "
                            "(reachability lead from CFG; no taint proof yet).",
            ))

    # TODO(Aleena): taint -----------------------------------------------------
    #  1. pick source functions (recv, read, fgets, getenv, websGetVar, cgi param getters)
    #  2. state = proj.factory.call_state(src_addr, ...) with claripy.BVS input
    #  3. simgr = proj.factory.simgr(state); simgr.use_technique(angr.exploration_techniques.
    #       LengthLimiter(max_length=...)); step with a step/time budget (FR-3.4)
    #  4. on reaching a sink with a symbolic arg -> upgrade confidence to CONFIRMED and fill
    #     crash_state (fault_address, registers, overflow_offset, stack_hash). No payloads.
    return findings
