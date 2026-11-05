# Unit42-FirmwareX

Upload a public, open-source IoT/router firmware image. The engine unpacks it, runs a static
hardening audit on every binary, looks for sink-reachability leads with angr, scans for hardcoded
secrets and weak crypto (redacted), and serves a CWE-classified report through a REST API and a
dashboard — all inside a network-isolated, resource-capped sandbox.

**Analysis only.** No exploit generation, no live devices, public/licensed firmware only.

See [`docs/architecture.md`](docs/architecture.md) for the architecture diagram, component
breakdown and containment design.

## Contributors

| Name | Contribution |
|---|---|
| **Habebur Rahman** | Project setup & GitHub, FastAPI backend, unpacker (binwalk/sasquatch fallback chain), ELF hardening audit, sandbox/containment design, pipeline orchestration, SQLite + hash-chained audit log, dashboard, debugging the real sandbox permission bug (`CAP_DAC_OVERRIDE`) found while testing on real firmware, Docker build + containment evidence |
| **Aleena K Mani** | Secret/crypto scanner patterns (API keys, JWT, default creds, entropy detection) + tests, angr sink-reachability stage (CFG recovery, source-to-sink matching, budgeted execution), architecture diagram review |

Roughly even split by scope: Habebur on infrastructure/pipeline/containment, Aleena on the
detection logic (secrets + angr). See the commit history and pull requests for the exact diffs
each contributed.

---

## 1. What you need before you start

| Tool | Why | Required? |
|---|---|---|
| **Git** | to clone this repo | Yes |
| **Python 3.11 or newer** | runs the API and analysis pipeline | Yes |
| **Docker Desktop** | runs the isolated sandbox container (binwalk, sasquatch, angr all run inside it for a real, contained analysis) | Yes, for a genuinely contained run. You *can* run without it in a reduced "dev mode" — see §6 — but then nothing is actually isolated, which defeats the point of this project |
| **WSL2 (Windows only)** | Docker Desktop and the Linux analysis tools need a Linux environment; on Windows this is WSL2 | Yes, if you're on Windows |
| **~10 GB free disk space** | Docker images, Python packages (`angr` alone is large), and firmware extraction all need room | Yes — see the troubleshooting note on this, it *will* cause strange failures if ignored |

If you're on **macOS or Linux**, skip straight to §3 — you already have a Linux-like shell and
don't need WSL.

If you're on **Windows**, do §2 first.

---

## 2. Windows-only: set up WSL2

Everything in this project (Python venv, Docker, binwalk, sasquatch) needs to run **inside WSL**,
not in a plain Windows PowerShell/CMD window. PowerShell doesn't understand `&&`, `source`, or any
of the Linux commands used below — if you type them into PowerShell you will get errors like
`The token '&&' is not a valid statement separator`.

**2.1 Install WSL2 and Ubuntu**

Open PowerShell **as Administrator** and run:

```powershell
wsl --install
```

This installs WSL2 and an Ubuntu distribution. Restart your PC when it asks you to.

> If you get `A distribution with the supplied name already exists`, WSL is already installed —
> skip to the next step.

**2.2 First launch**

Open the **Ubuntu** app from the Start menu (or type `wsl` in PowerShell). The first time, it asks
you to create a Unix username and password. **Remember this password** — you'll need it for every
`sudo` command below, and the characters won't show on screen while you type (that's normal).

> **Forgot your WSL password?** Open PowerShell and run `wsl -u root`, which logs you in as root
> without needing a password. Then run `passwd <your-username>` (find your username by running
> `ls /home` first) to set a new one, then `exit`.

**2.3 Keep your project files off the Windows (`C:`/`D:`) drive path when possible**

You *can* work from `/mnt/d/...` (a Windows drive, visible inside WSL), but Linux tools extracting
firmware filesystems sometimes behave oddly on Windows-formatted drives (permissions, symlinks).
If you hit strange extraction errors, try moving the project into your WSL home directory instead
(`~/firmwarex`) and working from there.

**2.4 Check your free disk space regularly**

WSL's entire Linux filesystem lives in one virtual disk file on your `C:` drive. If `C:` runs low
on space, WSL itself can start failing in confusing ways — commands like `ls` or `git` will error
with `Input/output error`, or WSL may refuse to start at all (`Catastrophic failure`). Check from
PowerShell:

```powershell
Get-PSDrive C | Select-Object Used, Free
```

Keep at least **10 GB free**. If you're low, run Disk Cleanup, empty the Recycle Bin, or move large
files off `C:`, then run `wsl --shutdown` followed by `wsl` to restart cleanly.

---

## 3. Clone the repository

From here on, every command runs **inside your Linux shell** (WSL's Ubuntu terminal, or your
native terminal on macOS/Linux).

```bash
git clone https://github.com/rahman56661/frimwarex.git
cd frimwarex
```

---

## 4. Install the Python dependencies

**4.1 Install Python build tools (Linux/WSL only — skip on macOS if you already have Python 3.11+)**

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip binwalk squashfs-tools build-essential \
  zlib1g-dev liblzma-dev liblzo2-dev liblz4-dev libzstd-dev git
```

This installs: Python's virtual-environment tool, `binwalk`/`squashfs-tools` (used by the local
dev-mode fallback — the real sandbox has its own copies), and the compiler + libraries needed to
build `sasquatch` in the next optional step.

**4.2 Create and activate a virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Your prompt should now start with `(.venv)`. **Every command below assumes this is active** — if
you close and reopen your terminal, run `source .venv/bin/activate` again before doing anything
else.

> On native Windows PowerShell (not WSL) the activation command is different:
> `.\.venv\Scripts\Activate.ps1`. You may first need to run
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` once if PowerShell refuses
> to run the script. This project is only tested end-to-end through WSL, though — plain PowerShell
> is missing `binwalk` and Docker's Linux containers won't run natively there.

**4.3 Install the Python packages**

```bash
pip install -r requirements.txt
```

This includes `angr`, which is a large package — installation can take 5–10 minutes. This is
normal; let it finish.

> **Error: a protobuf version mismatch when you later run the app** (something like
> `VersionError: Detected incompatible Protobuf Gencode/Runtime versions`) — run
> `pip install -U protobuf` and try again.

---

## 5. Install Docker Desktop and connect it to WSL

Docker runs the actual sandboxed analysis container — this is what makes the "isolated, no
network" claim true rather than just a comment in the code.

**5.1 Install**

Download and install Docker Desktop from <https://www.docker.com/products/docker-desktop>. During
setup, make sure **"Use WSL 2 instead of Hyper-V"** is selected (you can also check this later
under Docker Desktop → Settings → General → "Choose Virtual Machine Manager (VMM)" → should say
**WSL 2**).

**5.2 Turn on WSL integration for your distro**

Open Docker Desktop → **Settings → Resources → WSL integration**. Turn on the toggle for your
Ubuntu distro specifically (there's a master "Enable integration with my default WSL distro"
toggle, and then a per-distro toggle below it — both need to be on). Click **Apply & Restart**.

**5.3 Close and reopen your WSL terminal**, then verify:

```bash
docker --version
docker run hello-world
```

The second command should print `Hello from Docker!`. If instead you see:

```
failed to connect to the docker API at unix:///var/run/docker.sock: ... no such file or directory
```

— WSL integration isn't turned on for your distro yet. Go back to step 5.2, confirm **both**
toggles are on for your specific distro (not just the default-distro toggle), Apply & Restart, then
fully close your WSL terminal window and open a new one (a `source`-level refresh isn't enough —
the terminal needs a fresh session).

---

## 6. Build the sandbox image

```bash
docker compose --profile build build sandbox
```

This builds `fwx-sandbox:latest` — the container every analysis actually runs inside. It installs
binwalk, squashfs-tools, QEMU, and compiles `sasquatch` (a patched `unsquashfs` that can extract
the non-standard/old SquashFS format many router firmware images use, which the stock
`unsquashfs` can't). This step takes a few minutes the first time; Docker caches it afterwards, so
later builds after a small code change are much faster.

---

## 7. Run the server

```bash
export FWX_DATA=~/fwx-data
uvicorn app.main:app --reload
```

Open **http://localhost:8000** in your browser. Choose a firmware image and click **Analyse
image**.

Good public test images: any [OpenWrt](https://downloads.openwrt.org) `squashfs-sysupgrade.bin`
release, or [DVRF](https://github.com/praetorian-inc/DVRF)'s `Firmware/DVRF_v03.bin` (a small,
intentionally-vulnerable MIPS router image — the one this project was validated against).

**Dev mode, without Docker** (only for quick local iteration — this is *not* a contained run):

```bash
FWX_SANDBOX=local uvicorn app.main:app --reload
```

This mode is logged as `WARNING:uncontained_run` in the audit log, so it can never be mistaken for
a real, isolated run when reviewing evidence.

---

## 8. Verify the sandbox is actually isolated

```bash
docker run --rm --network none fwx-sandbox:latest ping -c1 1.1.1.1
```

Expected output: `ping: connect: Network is unreachable` — proof the sandbox has zero network
access, as required.

---

## 9. Run the test suite

```bash
pytest -q
```

Expect `17 passed`. These tests cover the data schema, the ELF hardening audit, secret redaction
(explicitly asserting the raw secret never appears anywhere in the output), the sandbox's `docker
run` command construction (network/capability/quota flags), the tamper-evident audit log, and a
full end-to-end run through the API against a synthetic firmware image. `tests/test_angr.py`
additionally compiles a small vulnerable C program on the fly and checks angr correctly finds the
sink and its input source.

---

## 10. Troubleshooting

These are real problems encountered while building and testing this project, with the fix that
worked.

| Symptom | Cause | Fix |
|---|---|---|
| `The token '&&' is not a valid statement separator` | You typed a Linux/bash command into Windows PowerShell | Open WSL (`wsl` in PowerShell, or the Ubuntu app) and run the command there instead |
| `.venv\Scripts\activate : The module '.venv' could not be loaded` | Same — PowerShell venv activation syntax is different, and this project's Linux-only tools (binwalk etc.) aren't available there anyway | Use WSL, and `source .venv/bin/activate` |
| WSL commands suddenly all fail with `Input/output error`, or `wsl` itself fails with `Catastrophic failure` | Your Windows `C:` drive ran out of space (WSL's virtual disk lives there) | Free up space on `C:` (Disk Cleanup, empty Recycle Bin), then `wsl --shutdown` followed by `wsl` |
| `Analysis failed: ... binwalk not installed (local mode)` | You're running `FWX_SANDBOX=local` but binwalk isn't installed on your WSL system | `sudo apt install -y binwalk squashfs-tools` |
| `unsquashfs rc=1 ... Can't find a valid SQUASHFS superblock` on a firmware image that *does* contain SquashFS | Some routers (DVRF included) use an old/non-standard SquashFS variant the stock `unsquashfs` can't read | Already handled: the pipeline falls back to a patched `sasquatch` extractor automatically. If you're running in `local` dev mode (not Docker), you need `sasquatch` installed on your host too — see the "Dev-mode-only: building sasquatch locally" note below |
| `failed to connect to the docker API at unix:///var/run/docker.sock` | Docker Desktop's WSL integration isn't enabled for your distro | See §5.2 — enable it for your *specific* distro, Apply & Restart, then open a fresh WSL terminal |
| `docker run ... ping: executable file not found in $PATH` when testing containment | The sandbox base image doesn't ship `ping` by default | Already fixed in `Dockerfile.sandbox` (adds `iputils-ping`) — rebuild the image (`docker compose --profile build build sandbox`) if you're on an older copy |
| `FATAL ERROR: dir_scan: failed to make directory ..., Permission denied` during a Docker-mode run | The sandbox container drops all Linux capabilities for security, including the one that normally lets root bypass file permissions — so it couldn't write into a work directory owned by your host user | Already fixed in `app/unpacker.py` (the work directory is made world-writable before the sandbox mounts it) — make sure you're on the latest `main` |
| `git push` rejected with `GH013: ... Push cannot contain secrets` | GitHub's secret scanner matched something in your diff that *looks* like a real API token/key format, even if it's fake test data | Don't hardcode realistic-looking secrets as plain string literals in committed files — build them from parts at runtime (e.g. `b"xoxb-" + b"..."` instead of one literal string) so they never appear as a scannable literal in the diff. If it's already in your commit history, rewrite history before pushing: `git reset --soft origin/main`, fix the file, re-add, re-commit, push |
| `git push` says `has no upstream branch` | You created a new local branch but never linked it to GitHub | `git push --set-upstream origin <your-branch-name>` |
| `pip install angr` fails or errors on import with a protobuf version message | Version mismatch between `angr`'s bundled protobuf code and your installed `protobuf` package | `pip install -U protobuf` |

**Dev-mode-only: building `sasquatch` locally** (skip this if you always run through Docker, which
already has it built in):

```bash
sudo apt install -y build-essential zlib1g-dev liblzma-dev liblzo2-dev liblz4-dev libzstd-dev
git clone --depth 1 https://github.com/onekey-sec/sasquatch /tmp/sasquatch
make -C /tmp/sasquatch/squashfs-tools -j4 sasquatch
sudo install -m 0755 /tmp/sasquatch/squashfs-tools/sasquatch /usr/local/bin/sasquatch
```

---

## 11. API reference

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/firmware/upload` | Upload an image, starts the pipeline, returns `firmware_id` + `job_id` |
| `GET /api/v1/firmware/{id}` | Status + summary |
| `GET /api/v1/firmware/{id}/filesystem` | Extracted file-tree inventory |
| `GET /api/v1/firmware/{id}/binary-audit` | Per-binary hardening matrix |
| `GET /api/v1/firmware/{id}/vulnerabilities` | Findings (filterable by `risk`, `category`) |
| `GET /api/v1/firmware/{id}/report` | Everything: summary, audit matrix, findings, audit log, chain-validity |
| `GET /api/v1/jobs/{job_id}` | Job status and per-stage timings |

---

## 12. Verified result (real firmware, fully contained)

Run against `DVRF_v03.bin` (public, [praetorian-inc/DVRF](https://github.com/praetorian-inc/DVRF)):

- 446 files extracted, 218 MIPSEL ELF binaries audited
- 394 findings: 1 critical (hardcoded private key, redacted), several high (network-facing `httpd`
  calling `system`/`popen`/`strcpy` with no stack canary and NX disabled)
- 100 angr reachability findings with a real input source in the call chain (e.g. `nvram_get` →
  `strcpy` in `set_passwd`, `delete_user_account`)
- 112.99s total run time (well inside the <30 min budget), `"Ran contained": true`
- Containment verified: `docker run --network none` cannot reach the network

---

## 13. Known limitations

- Full-system/network emulation (standing up a live emulated network service under QEMU) is not
  implemented — the spec itself calls this an open research problem; out of scope for this build.
- The angr stage produces a **CFG-reachability lead** (source and sink appear in the same call
  chain), not a data-flow proof. `crash_state` fields are placeholders until real symbolic
  execution/taint tracking is added.
- No fuzzing, no interactive CFG visualiser, no OpenTelemetry tracing (all listed as "Should", not
  "Must", in the spec).
- SQLite is used in place of PostgreSQL + Redis + Celery; the `Finding`/`BinaryAudit` schema maps
  directly if migrated later.
- Findings are capped at 100 per binary for the angr stage, to keep runs bounded — see
  `FWX_ANGR_MAX_BINARIES`, `FWX_ANGR_TIMEOUT` in `app/taint_angr.py` / `app/pipeline.py` if you
  need to raise these for a deeper run.

---

## 14. Safety rules this project follows

- No exploit code is ever generated — `crash_state` is diagnostic only (register/offset/path).
- Every tool that touches an untrusted image runs with zero network egress and per-job
  CPU/memory/time quotas.
- Detected secrets are **never stored raw** — only a salted SHA-256 fingerprint and length.
- Only public, open-source firmware is analysed — no real devices, no networks not owned by the
  analyst.
- The audit log is append-only and hash-chained; tampering is detectable (`pytest -q` includes a
  test that proves this).