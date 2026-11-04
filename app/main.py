"""FirmwareX API (PRD section 8.1)."""
from __future__ import annotations

import hashlib
import json
import os
import uuid

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .pipeline import run_pipeline

MAX_UPLOAD = int(os.environ.get("FWX_MAX_UPLOAD_MB", "256")) * 1024 * 1024
app = FastAPI(title="Unit42-FirmwareX", version="0.1.0")
STATIC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")


def _fw(fid: str) -> dict:
    with db.conn() as c:
        r = c.execute("SELECT * FROM firmware WHERE id=?", (fid,)).fetchone()
    if not r:
        raise HTTPException(404, "firmware not found")
    return dict(r)


def _ready(fid: str) -> dict:
    fw = _fw(fid)
    if fw["status"] != "done":
        raise HTTPException(409, f"analysis not complete (status={fw['status']})")
    return fw


@app.post("/api/v1/firmware/upload", status_code=202)
async def upload(bg: BackgroundTasks, file: UploadFile = File(...)):
    fid, job_id = str(uuid.uuid4()), str(uuid.uuid4())
    dest_dir = os.path.join(db.DATA_DIR, "uploads")
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, fid + ".bin")   # never use the client filename on disk
    h, size = hashlib.sha256(), 0
    with open(dest, "wb") as out:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > MAX_UPLOAD:
                out.close(); os.remove(dest)
                raise HTTPException(413, f"image exceeds {MAX_UPLOAD // 1024 // 1024} MB limit")
            h.update(chunk); out.write(chunk)
    with db.conn() as c:
        c.execute("INSERT INTO firmware VALUES(?,?,?,?,?,?,?)",
                  (fid, os.path.basename(file.filename or "unnamed"), h.hexdigest(), size, "queued", db.now(), None))
        c.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)",
                  (job_id, fid, "queued", "running", db.now(), None, None, "{}"))
    db.audit(fid, "ingest", {"filename": file.filename, "sha256": h.hexdigest(), "size": size})
    bg.add_task(run_pipeline, fid, dest, job_id)
    return {"firmware_id": fid, "job_id": job_id, "status": "queued"}


@app.get("/api/v1/firmware/{fid}")
def status(fid: str):
    fw = _fw(fid)
    fw["summary"] = json.loads(fw["summary"]) if fw["summary"] else None
    with db.conn() as c:
        j = c.execute("SELECT id FROM jobs WHERE firmware_id=?", (fid,)).fetchone()
    fw["job_id"] = j["id"] if j else None
    return fw


@app.get("/api/v1/firmware/{fid}/filesystem")
def filesystem(fid: str):
    _ready(fid)
    return {"firmware_id": fid, "files": db.get_artifact(fid, "filesystem") or []}


@app.get("/api/v1/firmware/{fid}/binary-audit")
def binary_audit(fid: str):
    _ready(fid)
    return {"firmware_id": fid, "binaries": db.get_artifact(fid, "binary_audit") or []}


@app.get("/api/v1/firmware/{fid}/vulnerabilities")
def vulnerabilities(fid: str, risk: str | None = None, category: str | None = None):
    _ready(fid)
    f = db.get_findings(fid)
    if risk:
        f = [x for x in f if x["risk_rating"] == risk]
    if category:
        f = [x for x in f if x["category"] == category]
    return {"firmware_id": fid, "count": len(f), "findings": f}


@app.get("/api/v1/firmware/{fid}/report")
def report(fid: str):
    fw = _ready(fid)
    return {
        "firmware_id": fid, "filename": fw["filename"], "sha256": fw["sha256"],
        "summary": json.loads(fw["summary"]),
        "binary_audit": db.get_artifact(fid, "binary_audit"),
        "findings": db.get_findings(fid),
        "audit_log": db.audit_rows(fid),
        "audit_chain_valid": db.verify_audit_chain(),
    }


@app.get("/api/v1/jobs/{job_id}")
def job(job_id: str):
    with db.conn() as c:
        r = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not r:
        raise HTTPException(404, "job not found")
    d = dict(r)
    d["stages"] = json.loads(d["stages"] or "{}")
    return d


@app.get("/healthz")
def healthz():
    return {"ok": True}


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))
