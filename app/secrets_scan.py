"""Secret + weak-crypto scanner with redaction (FR: secret/crypto scanning, SC-3.1/3.2).

RAW SECRETS ARE NEVER RETURNED OR PERSISTED. Only a salted SHA-256 fingerprint,
the kind of secret and its length leave this module.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from typing import Iterator, List, Optional, Tuple

from .schema import Arch, Category, Confidence, Finding, Risk

SALT = os.environ.get("FWX_SALT", "fwx-dev-salt-change-me").encode()
MAX_FILE = 20 * 1024 * 1024
STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")


def fingerprint(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(SALT + value).hexdigest()[:24]


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


# (name, regex over a printable string, CWE, risk)
SECRET_PATTERNS: List[Tuple[str, re.Pattern, str, Risk]] = [
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "CWE-321", Risk.CRITICAL),
    ("aws_access_key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b"), "CWE-798", Risk.HIGH),
    ("shadow_hash", re.compile(rb"^[a-z_][a-z0-9_-]*:\$(?:1|5|6|y)\$[^:]{4,}:"), "CWE-798", Risk.HIGH),
    ("url_credentials", re.compile(rb"[a-z]{3,8}://[^/\s:@]{1,32}:([^/\s:@]{3,64})@"), "CWE-798", Risk.HIGH),
    ("google_api_key", re.compile(rb"\b(AIza[0-9A-Za-z_\-]{35})\b"), "CWE-798", Risk.HIGH),
    ("slack_token", re.compile(rb"\b(xox[abprs]-[0-9A-Za-z-]{10,})\b"), "CWE-798", Risk.HIGH),
    ("jwt", re.compile(rb"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"), "CWE-798", Risk.MEDIUM),
    ("default_credentials",
     re.compile(rb"(?i)\b((?:admin|root|user|guest|support):(?:admin|root|1234|12345|password|guest|user|support))\b"),
     "CWE-798", Risk.MEDIUM),
    ("password_assignment",
     re.compile(rb"(?i)(?<![a-z])(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|token)(?![a-z])\s*[=:]\s*['\"]?([^\s'\"]{4,64})"),
     "CWE-798", Risk.MEDIUM),
]
STRONG_SIGNATURES = ("private_key", "aws_access_key", "shadow_hash", "google_api_key", "slack_token", "jwt")
CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----")

# weak crypto indicators: (label, regex, CWE, risk)
WEAK_CRYPTO = [
    ("MD5", re.compile(rb"\b(?:MD5_Init|MD5Init|md5_init|EVP_md5|md5sum|MD5_Update)\b"), "CWE-328", Risk.MEDIUM),
    ("SHA-1", re.compile(rb"\b(?:SHA1_Init|EVP_sha1|sha1_init|SHA1Init)\b"), "CWE-328", Risk.LOW),
    ("DES", re.compile(rb"\b(?:DES_ecb_encrypt|DES_set_key|DES_ncbc_encrypt|EVP_des_\w+)\b"), "CWE-327", Risk.HIGH),
    ("RC4", re.compile(rb"\b(?:RC4_set_key|RC4\b|EVP_rc4|arcfour)\b"), "CWE-327", Risk.HIGH),
]
# Don't flag lines that are obviously placeholders.
HIGH_ENTROPY_RE = re.compile(rb"[A-Za-z0-9+/=_-]{32,128}")
ENTROPY_MIN = 4.7
# alphabets / lookup tables look random-ish but are not secrets
TABLE_MARKERS = (b"ABCDEFGHIJ", b"abcdefghij", b"0123456789", b"abcdef0123")


def looks_like_secret_token(tok: bytes) -> bool:
    if any(m in tok for m in TABLE_MARKERS):
        return False
    has_digit = any(48 <= c <= 57 for c in tok)
    has_alpha = any(65 <= c <= 90 or 97 <= c <= 122 for c in tok)
    return has_digit and has_alpha and shannon(tok) >= ENTROPY_MIN


PLACEHOLDER = re.compile(rb"(?i)^(?:\*+|x+|null|none|changeme|example|<.*>|%s|\$\{?\w+\}?|password|passwd)$")


def _iter_files(rootfs: str) -> Iterator[Tuple[str, str]]:
    root_real = os.path.realpath(rootfs)
    for dirpath, _dirs, files in os.walk(rootfs, followlinks=False):
        for fn in files:
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue
            if not os.path.realpath(full).startswith(root_real):
                continue
            try:
                if os.path.getsize(full) > MAX_FILE or os.path.getsize(full) == 0:
                    continue
            except OSError:
                continue
            yield full, "/" + os.path.relpath(full, rootfs).replace(os.sep, "/")


def is_elf_bytes(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def scan_data(data: bytes, rel: str, firmware_id: str, arch: Arch = Arch.UNKNOWN,
              check_entropy: bool = True) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for m in STRING_RE.finditer(data):
        s = m.group(0)
        for name, rx, cwe, risk in SECRET_PATTERNS:
            hit = rx.search(s)
            if not hit:
                continue
            secret = hit.group(1) if hit.groups() else hit.group(0)
            if PLACEHOLDER.match(secret):
                continue
            fp = fingerprint(secret)
            key = (name, fp)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                firmware_id=firmware_id, binary=rel, architecture=arch,
                category=Category.HARDCODED_SECRET, cwe=cwe,
                address=hex(m.start()),  # file offset, not a VA
                risk_rating=risk,
                confidence=Confidence.PROBABLE if name in STRONG_SIGNATURES else Confidence.HEURISTIC,
                evidence_ref=f"{name}:{fp}:len={len(secret)}", redacted=True,
                description=f"Possible hardcoded {name.replace('_', ' ')} (value redacted, fingerprint only).",
            ))
        for tm in (HIGH_ENTROPY_RE.finditer(s) if check_entropy else ()):
            tok = tm.group(0)
            if looks_like_secret_token(tok):
                fp = fingerprint(tok)
                if ("high_entropy_string", fp) not in seen:
                    seen.add(("high_entropy_string", fp))
                    findings.append(Finding(
                        firmware_id=firmware_id, binary=rel, architecture=arch,
                        category=Category.HARDCODED_SECRET, cwe="CWE-798", address=hex(m.start() + tm.start()),
                        risk_rating=Risk.LOW, confidence=Confidence.HEURISTIC,
                        evidence_ref=f"high_entropy_string:{fp}:len={len(tok)}", redacted=True,
                        description="High-entropy token (possible key/secret; value redacted, fingerprint only).",
                    ))
        if CERT_RE.search(s):
            fp = fingerprint(s)
            if ("certificate", fp) not in seen:
                seen.add(("certificate", fp))
                findings.append(Finding(
                    firmware_id=firmware_id, binary=rel, architecture=arch,
                    category=Category.HARDCODED_SECRET, cwe="CWE-321", address=hex(m.start()),
                    risk_rating=Risk.INFO, confidence=Confidence.PROBABLE,
                    evidence_ref=f"certificate:{fp}", redacted=True,
                    description="Embedded certificate (informational; check for matching private key).",
                ))
    for label, rx, cwe, risk in WEAK_CRYPTO:
        if rx.search(data):
            findings.append(Finding(
                firmware_id=firmware_id, binary=rel, architecture=arch,
                category=Category.WEAK_CRYPTO, cwe=cwe, risk_rating=risk,
                confidence=Confidence.HEURISTIC, evidence_ref=f"weak_crypto:{label}", redacted=False,
                description=f"References deprecated/weak primitive: {label}.",
            ))
    return findings


def scan_rootfs(rootfs: str, firmware_id: str, arch_by_path: Optional[dict] = None) -> List[Finding]:
    arch_by_path = arch_by_path or {}
    out: List[Finding] = []
    for full, rel in _iter_files(rootfs):
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            continue
        out.extend(scan_data(data, rel, firmware_id, arch_by_path.get(rel, Arch.UNKNOWN),
                              check_entropy=not is_elf_bytes(data)))
    return out
