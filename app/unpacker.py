"""Unpack + filesystem inventory (FR-1.1, FR-1.2).

Strategy: binwalk (matryoshka) inside the sandbox; fall back to unsquashfs / tar
so you still get a rootfs when binwalk can't identify the container.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
from typing import Dict, List, Optional

from . import sandbox


def _count_files(d: str) -> int:
    return sum(len(f) for _, _, f in os.walk(d))


def find_rootfs(extract_dir: str) -> Optional[str]:
    """Pick the directory that looks most like a Linux root (has etc + bin/usr/sbin) with most files."""
    best, best_n = None, 0
    for dirpath, dirs, _ in os.walk(extract_dir, followlinks=False):
        names = set(dirs)
        if "etc" in names and names & {"bin", "usr", "sbin", "lib"}:
            n = _count_files(dirpath)
            if n > best_n:
                best, best_n = dirpath, n
    return best


def _safe_extract_tar(path: str, dest: str) -> bool:
    try:
        with tarfile.open(path) as tf:
            base = os.path.realpath(dest)
            for m in tf.getmembers():
                target = os.path.realpath(os.path.join(dest, m.name))
                if not target.startswith(base) or m.isdev():
                    continue
                tf.extract(m, dest)  # nosec - members are path-checked above
        return True
    except (tarfile.TarError, OSError):
        return False


def unpack(firmware_path: str, work_dir: str, timeout: int = 600) -> Dict:
    """Returns {rootfs, method, contained, log}. Raises RuntimeError if nothing could be extracted."""
    out = os.path.join(work_dir, "extract")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out, exist_ok=True)
    in_dir, in_name = os.path.dirname(os.path.abspath(firmware_path)), os.path.basename(firmware_path)
    log: List[str] = []
    contained = True

    if sandbox.MODE == "local":
        binwalk_cmd = ["binwalk", "-e", "-M", "-C", out, firmware_path]
        mounts = []
    else:
        binwalk_cmd = ["binwalk", "-e", "-M", "-C", "/out", f"/in/{in_name}"]
        mounts = [(in_dir, "/in", "ro"), (out, "/out", "rw")]

    method = None
    try:
        r = sandbox.run(binwalk_cmd, mounts, timeout=timeout)
        contained = contained and r.contained
        log.append(f"binwalk rc={r.returncode}")
        rootfs = find_rootfs(out)
        if rootfs:
            method = "binwalk"
    except FileNotFoundError:
        log.append("binwalk not installed (local mode)")
        rootfs = None

    if not rootfs and (sandbox.MODE != "local" or shutil.which("unsquashfs")):
        dest = os.path.join(out, "unsquashfs-root")
        r = sandbox.run(
            ["unsquashfs", "-f", "-d", dest if sandbox.MODE == "local" else "/out/unsquashfs-root",
             firmware_path if sandbox.MODE == "local" else f"/in/{in_name}"],
            mounts, timeout=timeout)
        contained = contained and r.contained
        log.append(f"unsquashfs rc={r.returncode}")
        rootfs = find_rootfs(out)
        method = "unsquashfs" if rootfs else method

    if not rootfs and _safe_extract_tar(firmware_path, os.path.join(out, "tar")):
        log.append("tar fallback")
        rootfs = find_rootfs(out)
        method = "tar" if rootfs else method

    if not rootfs:
        raise RuntimeError("could not reconstruct a root filesystem; " + "; ".join(log))
    return {"rootfs": rootfs, "method": method, "contained": contained, "log": log}


def inventory(rootfs: str, hash_limit: int = 50 * 1024 * 1024) -> List[Dict]:
    """File-tree inventory: path, type, size, sha256 (FR-1.2). Symlinks are recorded, never followed."""
    items: List[Dict] = []
    for dirpath, dirs, files in os.walk(rootfs, followlinks=False):
        for name in sorted(dirs + files):
            full = os.path.join(dirpath, name)
            rel = "/" + os.path.relpath(full, rootfs).replace(os.sep, "/")
            try:
                if os.path.islink(full):
                    items.append({"path": rel, "type": "symlink", "size": 0, "sha256": None,
                                  "target": os.readlink(full)})
                elif os.path.isdir(full):
                    items.append({"path": rel, "type": "dir", "size": 0, "sha256": None})
                elif os.path.isfile(full):
                    size = os.path.getsize(full)
                    h = None
                    if size <= hash_limit:
                        d = hashlib.sha256()
                        with open(full, "rb") as f:
                            for chunk in iter(lambda: f.read(1 << 20), b""):
                                d.update(chunk)
                        h = d.hexdigest()
                    items.append({"path": rel, "type": "file", "size": size, "sha256": h})
            except OSError:
                continue
    return items
