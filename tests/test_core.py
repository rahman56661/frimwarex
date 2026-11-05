import json
import os
import shutil
import subprocess

import pytest

from app import db, sandbox
from app.elf_audit import audit_elf
from app.schema import Arch, Category, Confidence, Finding, Risk
from app.secrets_scan import scan_data

SECRET = b"Sup3rS3cretPw!"
KEY = b"-----BEGIN RSA PRIVATE KEY-----"


def test_finding_schema_roundtrip():
    f = Finding(firmware_id="x", binary="/bin/httpd", category=Category.MEMORY_CORRUPTION, cwe="CWE-120",
                risk_rating=Risk.HIGH, confidence=Confidence.HEURISTIC)
    again = Finding.model_validate_json(f.model_dump_json())
    assert again.vulnerability_id == f.vulnerability_id and again.status.value == "new"
    assert f.detected_at.endswith("Z")


def test_elf_audit_system_binary():
    a = audit_elf("/bin/ls", "/bin/ls")
    assert a is not None
    assert a.architecture == Arch.X86_64 and a.bits == 64 and a.endianness == "little"
    assert a.nx is True and a.stack_canary is True and a.pie is True   # modern distro build


def test_elf_audit_ignores_non_elf(tmp_path):
    p = tmp_path / "notelf"
    p.write_bytes(b"hello world")
    assert audit_elf(str(p)) is None


def test_secrets_are_redacted():
    blob = b"junk\x00password=" + SECRET + b"\x00more\x00" + KEY + b"\x00RC4_set_key\x00"
    fs = scan_data(blob, "/etc/conf", "fw1")
    dumped = json.dumps([f.model_dump(mode="json") for f in fs])
    assert SECRET.decode() not in dumped            # raw secret never leaves the scanner
    cats = {f.category for f in fs}
    assert Category.HARDCODED_SECRET in cats and Category.WEAK_CRYPTO in cats
    assert all(f.evidence_ref.startswith(("password_assignment:sha256:", "private_key:sha256:", "weak_crypto:")) for f in fs)
    assert all(f.redacted for f in fs if f.category == Category.HARDCODED_SECRET)


def test_placeholder_not_flagged():
    assert scan_data(b"password=changeme\x00", "/x", "fw") == []


def test_sandbox_denies_egress_and_sets_quotas():
    argv = sandbox.docker_argv("fwx-test", ["binwalk", "-e", "/in/x"], [("/tmp", "/in", "ro")], mem="512m", cpus="0.5")
    s = " ".join(argv)
    assert "--network none" in s
    assert "--memory 512m" in s and "--cpus 0.5" in s and "--pids-limit" in s
    assert "--cap-drop ALL" in s and "no-new-privileges" in s and "--read-only" in s
    assert "/tmp:/in:ro" in s


def test_audit_chain_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "isolated.db"))   # don't poison the shared test DB
    db.audit("t1", "a", {"k": 1}); db.audit("t1", "b", {"k": 2})
    assert db.verify_audit_chain()
    with db.conn() as c:
        c.execute("UPDATE audit_log SET detail='{\"k\": 99}' WHERE event='a'")
    assert not db.verify_audit_chain()


@pytest.mark.skipif(not shutil.which("mksquashfs") or not shutil.which("unsquashfs"), reason="squashfs-tools missing")
def test_end_to_end_api(tmp_path):
    from fastapi.testclient import TestClient
    from app.main import app

    root = tmp_path / "rootfs"
    for d in ("bin", "etc", "usr/lib"):
        (root / d).mkdir(parents=True)
    shutil.copy("/bin/ls", root / "bin" / "httpd")                 # name matches a network-service hint
    (root / "etc" / "config").write_bytes(b"admin_password=" + SECRET + b"\n")
    (root / "etc" / "server.pem").write_bytes(KEY + b"\nMIIB...\n")
    img = tmp_path / "fw.squashfs"
    subprocess.run(["mksquashfs", str(root), str(img), "-quiet", "-no-progress"], check=True, capture_output=True)

    c = TestClient(app)
    r = c.post("/api/v1/firmware/upload", files={"file": ("fw.bin", img.read_bytes())})
    assert r.status_code == 202
    fid = r.json()["firmware_id"]

    st = c.get(f"/api/v1/firmware/{fid}").json()
    assert st["status"] == "done", st
    paths = {f["path"] for f in c.get(f"/api/v1/firmware/{fid}/filesystem").json()["files"]}
    assert {"/bin/httpd", "/etc/config"} <= paths
    bins = c.get(f"/api/v1/firmware/{fid}/binary-audit").json()["binaries"]
    assert any(b["path"] == "/bin/httpd" and b["architecture"] == "x86_64" for b in bins)

    rep = c.get(f"/api/v1/firmware/{fid}/report").json()
    assert rep["audit_chain_valid"] is True
    assert SECRET.decode() not in json.dumps(rep)                  # redaction holds end to end
    cats = {f["category"] for f in rep["findings"]}
    assert "hardcoded_secret" in cats
    assert c.get(f"/api/v1/firmware/{fid}/vulnerabilities?category=hardcoded_secret").json()["count"] >= 2
    assert c.get("/api/v1/firmware/nope").status_code == 404


# ---- scanner patterns (added by Aleena's task) -------------------------------------------------
GOOGLE = b"AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
SLACK = b"xoxb-" + b"123456789012-" + b"abcdefghijklmnop"  # built at runtime so it never appears as a literal token in source/diffs
JWT = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
TOKEN = b"q8Zk3Vn7Lp2Xw9Rt5Yb1Hc6Jd4Fm0Sg8Ua3Ne7Kx"


@pytest.mark.parametrize("blob,label", [
    (b"key=" + GOOGLE, "google_api_key"),
    (b"slack " + SLACK, "slack_token"),
    (b"auth " + JWT, "jwt"),
    (b"login admin:admin now", "default_credentials"),
    (b"blob " + TOKEN, "high_entropy_string"),
])
def test_new_patterns_detect_and_redact(blob, label):
    fs = scan_data(blob + b"\x00", "/etc/x", "fw")
    labels = {f.evidence_ref.split(":")[0] for f in fs}
    assert label in labels
    dumped = json.dumps([f.model_dump(mode="json") for f in fs])
    for raw in (GOOGLE, SLACK, JWT, TOKEN, b"admin:admin"):
        if raw in blob:
            assert raw.decode() not in dumped            # raw value never in output
    assert all(f.redacted for f in fs if f.category == Category.HARDCODED_SECRET)


def test_lookup_tables_not_flagged_as_entropy_tokens():
    b64_table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\x00"
    assert [f for f in scan_data(b64_table, "/bin/x", "fw") if f.evidence_ref.startswith("high_entropy")] == []


def test_entropy_scan_skipped_for_elf_binaries(tmp_path):
    import shutil as _sh
    from app.secrets_scan import is_elf_bytes, scan_rootfs
    root = tmp_path / "rootfs" / "bin"
    root.mkdir(parents=True)
    _sh.copy("/bin/ls", root / "ls")
    assert is_elf_bytes((root / "ls").read_bytes())
    fs = scan_rootfs(str(tmp_path / "rootfs"), "fw")
    assert [f for f in fs if f.evidence_ref.startswith("high_entropy")] == []