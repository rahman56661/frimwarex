"""Static hardening audit (FR-1.3, FR-1.4). checksec-style, pure Python (pyelftools)."""
from __future__ import annotations

import os
from typing import Optional

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .schema import Arch, BinaryAudit

PF_X, PF_W = 1, 2
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1


def is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _arch(elf: ELFFile) -> Arch:
    m = elf["e_machine"]
    if m == "EM_MIPS":
        return Arch.MIPSEL if elf.little_endian else Arch.MIPS
    return {
        "EM_ARM": Arch.ARM32,
        "EM_AARCH64": Arch.ARM64,
        "EM_X86_64": Arch.X86_64,
        "EM_386": Arch.X86,
    }.get(m, Arch.UNKNOWN)


def audit_elf(path: str, rel_path: Optional[str] = None) -> Optional[BinaryAudit]:
    """Return a BinaryAudit for `path`, or None if it is not a parseable ELF."""
    if not is_elf(path):
        return None
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)

            # --- segments: NX, RELRO, RWX
            has_gnu_stack = False
            nx = False
            has_relro = False
            rwx = False
            for seg in elf.iter_segments():
                t = seg["p_type"]
                fl = seg["p_flags"]
                if t == "PT_GNU_STACK":
                    has_gnu_stack = True
                    nx = not (fl & PF_X)
                elif t == "PT_GNU_RELRO":
                    has_relro = True
                elif t == "PT_LOAD" and (fl & PF_X) and (fl & PF_W):
                    rwx = True
            if not has_gnu_stack:
                nx = False  # no PT_GNU_STACK => legacy executable stack

            # --- dynamic tags: BIND_NOW, DEBUG (PIE vs shared object)
            bind_now = False
            has_debug = False
            dyn = elf.get_section_by_name(".dynamic")
            if isinstance(dyn, DynamicSection):
                for tag in dyn.iter_tags():
                    k = tag.entry.d_tag
                    if k == "DT_BIND_NOW":
                        bind_now = True
                    elif k == "DT_FLAGS" and (tag.entry.d_val & DF_BIND_NOW):
                        bind_now = True
                    elif k == "DT_FLAGS_1" and (tag.entry.d_val & DF_1_NOW):
                        bind_now = True
                    elif k == "DT_DEBUG":
                        has_debug = True

            is_dyn = elf["e_type"] == "ET_DYN"
            pie = is_dyn and has_debug
            shared = is_dyn and not has_debug
            relro = "none" if not has_relro else ("full" if bind_now else "partial")

            # --- symbols: canary, fortify, imports
            names, imports = set(), []
            for secname in (".dynsym", ".symtab"):
                sec = elf.get_section_by_name(secname)
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        if not sym.name:
                            continue
                        names.add(sym.name)
                        if secname == ".dynsym" and sym["st_shndx"] == "SHN_UNDEF":
                            imports.append(sym.name)
            canary = "__stack_chk_fail" in names or "__stack_chk_guard" in names
            fortify = any(n.startswith("__") and n.endswith("_chk") and n != "__stack_chk_fail" for n in names)
            stripped = elf.get_section_by_name(".symtab") is None

            return BinaryAudit(
                path=rel_path or path,
                architecture=_arch(elf),
                endianness="little" if elf.little_endian else "big",
                bits=elf.elfclass,
                nx=nx,
                pie=pie,
                is_shared_object=shared,
                relro=relro,
                stack_canary=canary,
                fortify=fortify,
                stripped=stripped,
                rwx_segment=rwx,
                imports=sorted(set(imports)),
            )
    except Exception:  # corrupt/truncated ELF -- skip, never crash the pipeline
        return None
