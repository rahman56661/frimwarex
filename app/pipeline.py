"""Orchestrator: ingest -> unpack -> audit -> leads -> (angr) -> scan -> normalise -> report."""
from __future__ import annotations

import json
import os
import time
import traceback
from collections import Counter
from typing import Dict, List

from . import db, sandbox
from .elf_audit import audit_elf, is_elf
from .schema import Arch, BinaryAudit, Finding
from .secrets_scan import scan_rootfs
from .sinks import find_sink_leads
from .unpacker import inventory, unpack

OVERALL_BUDGET_S = int(os.environ.get("FWX_JOB_BUDGET", "1500"))   # KPI: < 30 min


def _stage(job_id: str, fid: str, name: str, stages: Dict, t0: float, **info) -> None:
    stages[name] = {"t": round(time.time() - t0, 2), **info}
    with db.conn() as c:
        c.execute("UPDATE jobs SET stage=?, stages=? WHERE id=?", (name, json.dumps(stages), job_id))
    db.audit(fid, f"stage:{name}", info)


def run_pipeline(fid: str, fw_path: str, job_id: str) -> None:
    t0 = time.time()
    stages: Dict = {}
    work = os.path.join(db.DATA_DIR, "work", fid)
    os.makedirs(work, exist_ok=True)
    try:
        db.audit(fid, "job:start", {"sandbox_mode": sandbox.MODE, "image": sandbox.IMAGE,
                                    "mem": sandbox.MEM, "cpus": sandbox.CPUS})
        if sandbox.MODE == "local":
            db.audit(fid, "WARNING:uncontained_run", "FWX_SANDBOX=local -- development only")

        # 1. unpack + inventory
        u = unpack(fw_path, work)
        rootfs = u["rootfs"]
        inv = inventory(rootfs)
        db.put_artifact(fid, "filesystem", inv)
        _stage(job_id, fid, "unpack", stages, t0, method=u["method"], files=len(inv), contained=u["contained"])

        # 2. static audit of every ELF
        audits: List[BinaryAudit] = []
        for it in inv:
            if it["type"] != "file" or it["size"] < 64:
                continue
            full = os.path.join(rootfs, it["path"].lstrip("/"))
            if is_elf(full):
                a = audit_elf(full, it["path"])
                if a:
                    audits.append(a)
        db.put_artifact(fid, "binary_audit", [a.public() for a in audits])
        _stage(job_id, fid, "audit", stages, t0, elfs=len(audits))

        findings: List[Finding] = []
        # 3. static leads (sinks, missing mitigations)
        findings += find_sink_leads(audits, fid)
        _stage(job_id, fid, "leads", stages, t0, count=len(findings))

        # 4. angr sink-reachability on the top network-facing binaries (budgeted, child process)
        angr_info = {"enabled": False}
        if os.environ.get("FWX_ANGR", "1") == "1":
            from . import taint_angr
            from .sinks import SERVICE_HINTS
            if taint_angr.available():
                targets = [a for a in audits if not a.is_shared_object and any(h in a.path.lower() for h in SERVICE_HINTS)]
                targets = targets[: int(os.environ.get("FWX_ANGR_MAX_BINARIES", "5"))]
                got, incomplete = [], []
                for a in targets:
                    fs, ok, note = taint_angr.analyse_binary(os.path.join(rootfs, a.path.lstrip("/")), a.path, fid, a.architecture)
                    got += fs
                    if not ok:
                        incomplete.append({"binary": a.path, "reason": note})
                keys = {(f.binary, f.sink) for f in got}            # angr result supersedes the heuristic lead
                findings = [f for f in findings if not (f.evidence_ref.startswith("import:") and (f.binary, f.sink) in keys)]
                findings += got
                angr_info = {"enabled": True, "binaries": len(targets), "findings": len(got), "incomplete": incomplete}
            else:
                angr_info = {"enabled": False, "reason": "angr not installed"}
        _stage(job_id, fid, "taint", stages, t0, **angr_info)

        # 5. secrets + weak crypto (redacted)
        arch_by_path = {a.path: a.architecture for a in audits}
        sec = scan_rootfs(rootfs, fid, arch_by_path)
        findings += sec
        _stage(job_id, fid, "secrets", stages, t0, count=len(sec))

        # 6. normalise + persist
        db.put_findings(fid, findings)
        summary = {
            "files": len(inv), "elfs": len(audits), "findings": len(findings),
            "by_risk": dict(Counter(f.risk_rating.value for f in findings)),
            "by_category": dict(Counter(f.category.value for f in findings)),
            "architectures": dict(Counter(a.architecture.value for a in audits)),
            "unpack_method": u["method"], "contained": u["contained"],
            "duration_s": round(time.time() - t0, 2),
            "within_budget": (time.time() - t0) < OVERALL_BUDGET_S,
        }
        with db.conn() as c:
            c.execute("UPDATE firmware SET status='done', summary=? WHERE id=?", (json.dumps(summary), fid))
            c.execute("UPDATE jobs SET status='done', finished_at=? WHERE id=?", (db.now(), job_id))
        db.audit(fid, "job:done", summary)
    except Exception as e:  # noqa: BLE001 - job boundary
        with db.conn() as c:
            c.execute("UPDATE firmware SET status='failed' WHERE id=?", (fid,))
            c.execute("UPDATE jobs SET status='failed', finished_at=?, error=? WHERE id=?",
                      (db.now(), str(e)[:500], job_id))
        db.audit(fid, "job:failed", {"error": str(e)[:500], "trace": traceback.format_exc()[-800:]})
