"""Containment (PRD section 7). Untrusted-image tooling runs in an egress-denied container.

SC-1.1  --network none                 (zero egress)
SC-1.3  --cap-drop ALL, no-new-privileges, pids-limit
SC-2.1  --memory / --cpus / wall-clock timeout -> `docker kill`

FWX_SANDBOX=docker (default) | local.  `local` is DEV ONLY (no isolation) and is
written to the audit log so it can never be mistaken for a contained run.
"""
from __future__ import annotations

import os
import subprocess
import uuid
from dataclasses import dataclass
from typing import List, Optional, Tuple

IMAGE = os.environ.get("FWX_SANDBOX_IMAGE", "fwx-sandbox:latest")
MODE = os.environ.get("FWX_SANDBOX", "docker")
MEM = os.environ.get("FWX_JOB_MEM", "1g")
CPUS = os.environ.get("FWX_JOB_CPUS", "1.0")
PIDS = os.environ.get("FWX_JOB_PIDS", "256")


class SandboxTimeout(Exception):
    pass


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    contained: bool
    container: Optional[str]


def docker_argv(name: str, cmd: List[str], mounts: List[Tuple[str, str, str]],
                mem: str = MEM, cpus: str = CPUS, pids: str = PIDS) -> List[str]:
    """Build the docker command. Pure function -> easy to unit test (containment evidence)."""
    argv = [
        "docker", "run", "--rm", "--name", name,
        "--network", "none",
        "--memory", mem, "--memory-swap", mem, "--cpus", cpus, "--pids-limit", pids,
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--read-only", "--tmpfs", "/tmp:rw,size=256m",
    ]
    for host, ctr, mode in mounts:
        argv += ["-v", f"{os.path.abspath(host)}:{ctr}:{mode}"]
    return argv + [IMAGE] + cmd


def run(cmd: List[str], mounts: List[Tuple[str, str, str]], timeout: int = 300) -> SandboxResult:
    if MODE == "local":
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise SandboxTimeout(f"local run exceeded {timeout}s") from e
        return SandboxResult(p.returncode, p.stdout, p.stderr, contained=False, container=None)

    name = f"fwx-{uuid.uuid4().hex[:12]}"
    argv = docker_argv(name, cmd, mounts)
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        subprocess.run(["docker", "kill", name], capture_output=True)  # quota breach -> terminate
        raise SandboxTimeout(f"{name} exceeded {timeout}s and was killed") from e
    return SandboxResult(p.returncode, p.stdout, p.stderr, contained=True, container=name)
