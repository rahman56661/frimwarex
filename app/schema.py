"""Finding schema (PRD Appendix A). Every module normalises into `Finding`.

Crash state is diagnostic only -- no exploit artefacts are ever stored.
"""
from __future__ import annotations

import datetime as dt
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Arch(str, Enum):
    ARM32 = "ARM32"
    ARM64 = "ARM64"
    MIPS = "MIPS"
    MIPSEL = "MIPSEL"
    X86_64 = "x86_64"
    X86 = "x86"
    UNKNOWN = "UNKNOWN"


class Category(str, Enum):
    MEMORY_CORRUPTION = "memory_corruption"
    HARDCODED_SECRET = "hardcoded_secret"
    WEAK_CRYPTO = "weak_crypto"
    MISSING_MITIGATION = "missing_mitigation"
    COMMAND_INJECTION = "command_injection"


class Risk(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    HEURISTIC = "heuristic"


class Status(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"


class CrashState(BaseModel):
    fault_address: Optional[str] = None
    registers: Optional[Dict[str, str]] = None
    overflow_offset: Optional[int] = None
    stack_hash: Optional[str] = None


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


class Finding(BaseModel):
    vulnerability_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    firmware_id: str
    binary: str  # path inside rootfs
    architecture: Arch = Arch.UNKNOWN
    category: Category
    cwe: str
    address: Optional[str] = None
    sink: Optional[str] = None
    source: Optional[str] = None
    tainted_path: List[str] = Field(default_factory=list)
    crash_state: CrashState = Field(default_factory=CrashState)
    risk_rating: Risk
    confidence: Confidence
    evidence_ref: str = ""  # redacted artefact id / fingerprint -- never a raw secret
    redacted: bool = False
    status: Status = Status.NEW
    detected_at: str = Field(default_factory=_now)
    description: str = ""  # human-readable summary (extension to Appendix A)


class BinaryAudit(BaseModel):
    path: str
    architecture: Arch
    endianness: str
    bits: int
    nx: bool
    pie: bool
    is_shared_object: bool = False
    relro: str  # none | partial | full
    stack_canary: bool
    fortify: bool
    stripped: bool
    rwx_segment: bool = False
    imports: List[str] = Field(default_factory=list)

    def public(self) -> Dict[str, Any]:
        d = self.model_dump(mode="json")
        d.pop("imports", None)
        return d
