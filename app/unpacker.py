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


SQUASH_MAGICS = (b"hsqs", b"sqsh", b"shsq", b"qshs")      # std LE/BE + non-standard LE/BE (old Broadcom/DVRF)


def _squashfs_offsets(path: str, limit: int = 8) -> List[int]:
    import mmap
    offs: List[int] = []
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        for magic in SQUASH_MAGICS:
            i = mm.find(magic)
            while i != -1 and len(offs) < limit * 4:
                offs.append(i)
                i = mm.find(magic, i + 1)
    return sorted(set(offs))[:limit]


def _carve(src: str, dst: str, offset: int) -> None:
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fi.seek(offset)
        shutil.copyfileobj(fi, fo, 1 << 20)


def _sasquatch_fallback(firmware_path: str, out: str, timeout: int, log: List[str]):
    """Carve SquashFS at magic offsets and extract with sasquatch (handles v3 / non-standard / LZMA variants)."""
    if sandbox.MODE == "local" and not shutil.which("sasquatch"):
        log.append("sasquatch not installed")
        return None, True
    contained = True
    for off in _squashfs_offsets(firmware_path):
        carved = os.path.join(out, f"carve_{off:x}.squashfs")
        _carve(firmware_path, carved, off)
        for endian in ("-le", "-be"):
            dest_name = f"sasquatch-{off:x}{endian}"
            dest = os.path.join(out, dest_name)
            if sandbox.MODE == "local":
                cmd, mounts = ["sasquatch", "-p", "1", endian, "-d", dest, carved], []
            else:
                cmd = ["sasquatch", "-p", "1", endian, "-d", f"/out/{dest_name}", f"/out/{os.path.basename(carved)}"]
                mounts = [(out, "/out", "rw")]
            try:
                r = sandbox.run(cmd, mounts, timeout=timeout)
            except sandbox.SandboxTimeout:
                log.append(f"sasquatch {endian}@{off:#x}: timeout")
                continue
            contained = contained and r.contained
            err_tail = (r.stderr or r.stdout or "").strip().splitlines()
            err_tail = " | ".join(err_tail[-2:]) if err_tail else ""
            log.append(f"sasquatch {endian}@{off:#x} rc={r.returncode}" + (f" :: {err_tail[:200]}" if r.returncode else ""))
            root = find_rootfs(dest) if os.path.isdir(dest) else None
            if root:
                return root, contained
        os.remove(carved) if os.path.exists(carved) else None
    return None, contained


def unpack(firmware_path: str, work_dir: str, timeout: int = 600) -> Dict:
    """Returns {rootfs, method, contained, log}. Raises RuntimeError if nothing could be extracted."""
    out = os.path.join(work_dir, "extract")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out, exist_ok=True)
    if sandbox.MODE != "local":
        # The sandbox container drops ALL capabilities (SC-1.3), including CAP_DAC_OVERRIDE, so its
        # root user can no longer bypass Unix permission checks the way an uncontained root normally
        # would. Without this, the container gets "Permission denied" creating anything under the
        # bind-mounted work directory, since that directory is owned by the host user, not root.
        # World-writable is fine here: this is a short-lived, per-job scratch directory, not a secret.
        os.chmod(out, 0o777)
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
        tail = " | ".join((r.stderr or "").strip().splitlines()[-2:])
        log.append(f"binwalk rc={r.returncode}" + (f" :: {tail[:200]}" if r.returncode else ""))
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
        tail = " | ".join((r.stderr or "").strip().splitlines()[-2:])
        log.append(f"unsquashfs rc={r.returncode}" + (f" :: {tail[:200]}" if r.returncode else ""))
        rootfs = find_rootfs(out)
        method = "unsquashfs" if rootfs else method

    if not rootfs:
        rootfs, c = _sasquatch_fallback(firmware_path, out, timeout, log)
        contained = contained and c
        method = "sasquatch" if rootfs else method

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
