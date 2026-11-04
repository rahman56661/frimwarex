# Unit42-FirmwareX (one-day vertical slice)

Upload a public open-source firmware image -> unpack -> static hardening audit -> sink leads ->
secret/crypto scan (redacted) -> CWE-classified JSON report -> dashboard.
Analysis only. No exploits, no live devices, public firmware only.

## Run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1) sandbox image (needs Docker). Workers run with --network none, mem/cpu/pids limits, cap-drop ALL
docker compose --profile build build sandbox

# 2) API + dashboard  ->  http://localhost:8000
uvicorn app.main:app --reload

# no Docker on your laptop? DEV ONLY (uncontained, logged as WARNING in the audit log):
FWX_SANDBOX=local uvicorn app.main:app --reload

pytest -q
```

Test firmware (public): OpenWrt images, or DVRF (Damn Vulnerable Router Firmware).

## Who owns what

| Area | Files | Owner |
|---|---|---|
| API, DB, audit log, pipeline | `app/main.py`, `db.py`, `pipeline.py` | Habebur |
| Unpack + inventory + sandbox | `app/unpacker.py`, `sandbox.py`, `Dockerfile.sandbox` | Habebur |
| ELF hardening matrix | `app/elf_audit.py` | Habebur |
| Secret/crypto scanner + redaction | `app/secrets_scan.py` | Aleena |
| angr sink reachability / taint | `app/taint_angr.py` (skeleton, untested) | Aleena |
| Dashboard | `static/index.html` | Aleena |
| Finding schema (Appendix A) | `app/schema.py` | shared, freeze in hour 1 |

## Status

Done + tested: schema, ELF audit, unpack (binwalk -> unsquashfs -> tar fallback), inventory,
secret/crypto scan with fingerprint-only storage, sink leads, hash-chained audit log, REST API,
dashboard, containment argv test.
TODO: angr taint (`taint_angr.py`, then call it from `pipeline.py` step 4), real-firmware run,
containment evidence (docker egress test + quota kill), architecture diagram, write-up.

## Evidence checklist (PRD section 12)

- [ ] Unpack + mitigation matrix for a named image (screenshot of Mitigations tab)
- [ ] Sample JSON findings (`GET /api/v1/firmware/{id}/report`) incl. one redacted secret
- [ ] Containment: `docker run --network none fwx-sandbox ping -c1 1.1.1.1` fails; a job killed on timeout
- [ ] Redaction: grep report for the raw secret -> no match
- [ ] Screen recording upload -> report; throughput timing (`summary.duration_s`)
- [ ] `pytest --cov` report

## Known limitations

User-mode/full-system QEMU emulation and fuzzing are not implemented in this slice (best-effort per PRD);
SQLite instead of PostgreSQL; FastAPI BackgroundTasks instead of Celery/Redis; no gRPC / OpenTelemetry.
