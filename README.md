# Unit42-FirmwareX

Upload a public, open-source IoT/router firmware image. The engine unpacks it, runs a static
hardening audit on every binary, looks for sink-reachability leads with angr, scans for hardcoded
secrets and weak crypto (redacted), and serves a CWE-classified report through a REST API and a
dashboard — all inside a network-isolated, resource-capped sandbox.

**Analysis only.** No exploit generation, no live devices, public/licensed firmware only.

See [`docs/architecture.md`](docs/architecture.md) for the full architecture diagram, component
breakdown and containment design.

## Contributors

| Name | Contribution |
|---|---|
| **Habebur Rahman** | Project setup & GitHub, FastAPI backend, unpacker (binwalk/sasquatch fallback chain), ELF hardening audit, sandbox/containment design, pipeline orchestration, SQLite + hash-chained audit log, dashboard, debugging the real sandbox permission bug (`CAP_DAC_OVERRIDE`) found while testing on real firmware, Docker build + containment evidence |
| **Aleena K Mani** | Secret/crypto scanner patterns (API keys, JWT, default creds, entropy detection) + tests, angr sink-reachability stage (CFG recovery, source-to-sink matching, budgeted execution), architecture diagram review |

Roughly even split by scope: Habebur on infrastructure/pipeline/containment, Aleena on the
detection logic (secrets + angr). See the commit history and pull requests for the exact diffs
each contributed.

## Prerequisites

- Python 3.11+
- Docker Desktop (for the sandboxed analysis containers — required for a truly contained run)
- On Windows: WSL2 with a Linux distro (Ubuntu recommended), with Docker Desktop's WSL integration
  enabled for that distro
- `binwalk`, `squashfs-tools` (installed automatically inside the sandbox image; only needed on the
  host if you run in `FWX_SANDBOX=local` dev mode — see below)

## Clone and set up

```bash
git clone https://github.com/rahman56661/frimwarex.git
cd frimwarex

python3 -m venv .venv
source .venv/bin/activate          # Windows (not WSL): .venv\Scripts\Activate.ps1

pip install -r requirements.txt    # installs angr too — can take several minutes
```

## Build the sandbox image (required for a contained run)

```bash
docker compose --profile build build sandbox
```

This builds `fwx-sandbox:latest`: Ubuntu 24.04 with binwalk, squashfs-tools, a patched `sasquatch`
extractor (handles the non-standard/old SquashFS variants many router images use), QEMU user-mode
static binaries, and `iputils-ping` (so containment itself can be tested — see below).

## Run

```bash
export FWX_DATA=~/fwx-data          # where the SQLite DB and per-job work dirs live
uvicorn app.main:app --reload
```

Open `http://localhost:8000`, choose a firmware image, and click **Analyse image**. Public test
images: [OpenWrt](https://downloads.openwrt.org) squashfs-sysupgrade builds, or
[DVRF](https://github.com/praetorian-inc/DVRF) (`Firmware/DVRF_v03.bin`) — both are
public/open-source MIPS router firmware well suited to this pipeline.

Without Docker (development only, **not a contained run**):

```bash
FWX_SANDBOX=local uvicorn app.main:app --reload
```

This is logged to the audit log as `WARNING:uncontained_run` so a dev-mode run can never be
mistaken for a real contained one in the evidence.

## Verify containment (evidence)

```bash
docker run --rm --network none fwx-sandbox:latest ping -c1 1.1.1.1
```

Expected: `ping: connect: Network is unreachable` — the sandbox has zero network egress.

## Run the tests

```bash
pytest -q
```

17 tests, covering the schema, ELF audit, secret redaction (asserts the raw secret never appears
in output), the sandbox's `docker run` argv (network/cap/quota flags), the hash-chained audit log
(including tamper detection), and a full end-to-end API run against a synthetic firmware image.
`tests/test_angr.py` additionally builds a tiny vulnerable C binary and verifies angr finds the
`strcpy`/`system` sinks with the correct source and CWE.

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/firmware/upload` | Upload an image, starts the pipeline, returns `firmware_id` + `job_id` |
| `GET /api/v1/firmware/{id}` | Status + summary |
| `GET /api/v1/firmware/{id}/filesystem` | Extracted file-tree inventory |
| `GET /api/v1/firmware/{id}/binary-audit` | Per-binary hardening matrix |
| `GET /api/v1/firmware/{id}/vulnerabilities` | Findings (filterable by `risk`, `category`) |
| `GET /api/v1/firmware/{id}/report` | Everything: summary, audit matrix, findings, audit log, chain-validity |
| `GET /api/v1/jobs/{job_id}` | Job status and per-stage timings |

## Verified result (real firmware, fully contained)

Run against `DVRF_v03.bin` (public, [praetorian-inc/DVRF](https://github.com/praetorian-inc/DVRF)):

- 446 files extracted, 218 MIPSEL ELF binaries audited
- 394 findings: 1 critical (hardcoded private key, redacted), several high (network-facing `httpd`
  calling `system`/`popen`/`strcpy` with no stack canary and NX disabled)
- 100 angr reachability findings with a real input source in the call chain (e.g. `nvram_get` →
  `strcpy` in `set_passwd`, `delete_user_account`)
- 112.99s total run time (well inside the <30 min budget), `"Ran contained": true`
- Containment verified: `docker run --network none` cannot reach the network

## Known limitations

- Full-system/network emulation (standing up a live emulated network service under QEMU) is not
  implemented — the spec itself calls this an open research problem; out of scope for this build.
- The angr stage produces a **CFG-reachability lead** (source and sink appear in the same call
  chain), not a data-flow proof. `crash_state` fields are placeholders until real symbolic
  execution/taint tracking is added.
- No fuzzing, no interactive CFG visualiser, no OpenTelemetry tracing (all listed as "Should", not
  "Must", in the spec).
- SQLite is used in place of PostgreSQL + Redis + Celery; the `Finding`/`BinaryAudit` schema maps
  directly if migrated later.
- Findings are capped at 100 per binary for the angr stage and a few other heuristics, to keep
  runs bounded — see `FWX_ANGR_MAX_BINARIES`, `FWX_ANGR_TIMEOUT` in `app/taint_angr.py` /
  `app/pipeline.py` if you need to raise these for a deeper run.

## Safety rules this project follows

- No exploit code is ever generated — `crash_state` is diagnostic only (register/offset/path).
- Every tool that touches an untrusted image runs with zero network egress and per-job
  CPU/memory/time quotas.
- Detected secrets are **never stored raw** — only a salted SHA-256 fingerprint and length.
- Only public, open-source firmware is analysed — no real devices, no networks not owned by the
  analyst.
- The audit log is append-only and hash-chained; tampering is detectable (`pytest -q` includes a
  test that proves this).