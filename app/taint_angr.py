"""angr sink-reachability stage (FR-3.1, FR-3.2, FR-3.4).

What this does (validated on an x86_64 test binary; run it on a real MIPS/ARM firmware binary next):
  * recovers a CFG with angr (static -- the binary is parsed, never executed),
  * finds every function that calls a dangerous sink (strcpy/sprintf/memcpy/system/popen ...),
  * checks whether an input *source* (recv/read/getenv/fgets/websGetVar/...) is called by that
    function or by one of its callers up to 2 levels up -> PROBABLE lead with `source` filled in,
    otherwise a HEURISTIC lead.
What it does NOT do yet (honest limit): real data-flow taint / symbolic execution and crash state.
See the TODO block at the bottom -- that is the remaining Aleena work.

Budgets (FR-3.4 / SC-2.2): the whole analysis runs in a child process with a wall-clock timeout and an
address-space limit. On breach the child is killed and the result is reported as INCOMPLETE.
"""
from __future__ import annotations

import importlib.util
import multiprocessing as mp
import os
import queue
from typing import List, Tuple

from .schema import Arch, Category, Confidence, CrashState, Finding, Risk

TIMEOUT_S = int(os.environ.get("FWX_ANGR_TIMEOUT", "150"))      # per binary
MEM_LIMIT_MB = int(os.environ.get("FWX_ANGR_MEM_MB", "3000"))   # per binary
MAX_CALLERS_PER_SINK = 20
MAX_FINDINGS = 100

SINKS = {
    "strcpy": ("CWE-120", Category.MEMORY_CORRUPTION), "strcat": ("CWE-120", Category.MEMORY_CORRUPTION),
    "sprintf": ("CWE-120", Category.MEMORY_CORRUPTION), "vsprintf": ("CWE-120", Category.MEMORY_CORRUPTION),
    "gets": ("CWE-120", Category.MEMORY_CORRUPTION), "memcpy": ("CWE-787", Category.MEMORY_CORRUPTION),
    "system": ("CWE-78", Category.COMMAND_INJECTION), "popen": ("CWE-78", Category.COMMAND_INJECTION),
}
SOURCES = {
    "recv", "recvfrom", "recvmsg", "read", "fgets", "gets", "scanf", "fscanf", "getenv",
    "websGetVar", "cgiGetValue", "nvram_get", "nvram_safe_get", "getenv_s",
}


def available() -> bool:
    return importlib.util.find_spec("angr") is not None


def _analyse(path: str, rel: str, fid: str, arch: Arch) -> List[Finding]:
    import angr  # heavy; imported only inside the budgeted child process

    proj = angr.Project(path, auto_load_libs=False)
    # resolve_indirect_jumps=True matters on MIPS: external calls go through the GOT via
    # "la $t9, strcpy; jalr $t9" rather than a classic PLT stub, so without indirect-jump
    # resolution CFGFast never discovers strcpy/system/etc as named functions at all.
    cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True, force_complete_scan=False)
    funcs = cfg.functions
    cg = funcs.callgraph

    def name(a: int) -> str:
        f = funcs.get(a)
        return f.name if f is not None else hex(a)

    def callee_names(a: int) -> set:
        return {name(x) for x in cg.successors(a)} if a in cg else set()

    def caller_addrs(a: int) -> list:
        return list(cg.predecessors(a)) if a in cg else []

    by_name = {}
    for f in funcs.values():
        by_name.setdefault(f.name, f)

    out: List[Finding] = []
    for sink, (cwe, cat) in SINKS.items():
        sink_fn = by_name.get(sink)
        if sink_fn is None:
            continue
        for caller in caller_addrs(sink_fn.addr)[:MAX_CALLERS_PER_SINK]:
            if len(out) >= MAX_FINDINGS:
                return out
            chain, srcs = [caller], callee_names(caller) & SOURCES
            for up in caller_addrs(caller)[:10]:                 # 1 level up
                if srcs:
                    break
                s = callee_names(up) & SOURCES
                if s:
                    srcs, chain = s, [up, caller]
                    break
                for up2 in caller_addrs(up)[:10]:                # 2 levels up
                    s = callee_names(up2) & SOURCES
                    if s:
                        srcs, chain = s, [up2, up, caller]
                        break
                if srcs:
                    break
            src = sorted(srcs)[0] if srcs else None
            risk = Risk.HIGH if (src and cat == Category.COMMAND_INJECTION) else Risk.MEDIUM
            out.append(Finding(
                firmware_id=fid, binary=rel, architecture=arch, category=cat, cwe=cwe,
                address=hex(caller), sink=sink, source=src,
                tainted_path=[hex(a) for a in chain] + [hex(sink_fn.addr)],
                crash_state=CrashState(),                      # TODO: fill from a symbolic run
                risk_rating=risk,
                confidence=Confidence.PROBABLE if src else Confidence.HEURISTIC,
                evidence_ref="cfg:" + "->".join(name(a) for a in chain) + f"->{sink}",
                description=(f"`{name(caller)}` calls `{sink}`; input source `{src}` is called in the same call chain "
                             "(CFG reachability, no data-flow proof)." if src else
                             f"`{name(caller)}` calls `{sink}`; no input source found within 2 call levels."),
            ))
    return out


def _worker(path: str, rel: str, fid: str, arch_val: str, q) -> None:
    try:
        import resource
        limit = MEM_LIMIT_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))   # SC-2.1 memory quota (Linux)
    except Exception:  # noqa: BLE001 - non-Linux: skip, wall-clock budget still applies
        pass
    try:
        q.put([f.model_dump_json() for f in _analyse(path, rel, fid, Arch(arch_val))])
    except BaseException as e:  # noqa: BLE001 - includes MemoryError
        q.put(("error", f"{type(e).__name__}: {e}"[:300]))


def analyse_binary(path: str, rel: str, firmware_id: str, arch: Arch,
                   timeout: int = TIMEOUT_S) -> Tuple[List[Finding], bool, str]:
    """Returns (findings, complete, note). complete=False means a budget was hit or angr failed."""
    if not available():
        return [], False, "angr not installed"
    ctx = mp.get_context("spawn")   # fork inside a threaded web server can deadlock
    q = ctx.Queue()
    p = ctx.Process(target=_worker, args=(path, rel, firmware_id, arch.value, q), daemon=True)
    p.start()
    try:
        payload = q.get(timeout=timeout)
    except queue.Empty:
        p.terminate(); p.join(5)
        return [], False, f"timeout after {timeout}s"
    p.join(5)
    if isinstance(payload, tuple):
        return [], False, payload[1]
    return [Finding.model_validate_json(x) for x in payload], True, "ok"


# TODO (remaining work) -------------------------------------------------------------------------
#  Real taint / crash state: build a call_state at the source's caller with claripy.BVS input, step a
#  SimulationManager with a state/time budget (angr.exploration_techniques.LengthLimiter), and when a
#  state reaches the sink with a symbolic argument -> upgrade to CONFIRMED and fill crash_state
#  (fault_address, registers, overflow_offset, stack_hash). Diagnostic state only -- never a payload.
