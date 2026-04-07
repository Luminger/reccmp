"""Watcom Debug Info 3.0 parser.

Parses the debug section appended to the end of a DOS/4GW LE executable
when linked with ``DEBUG WATCOM ALL`` (or compiled with ``-hw``).

Layout (from wdbginfo.h)
========================

At the end of the file::

    [source language table]   ← lang_size bytes
    [segment address table]   ← seg_size bytes
    [section debug info]      ← section_size bytes; repeated per overlay
    [master debug header]     ← 14 bytes at EOF

Section debug info layout::

    [section header]          ← 18 bytes  (mod/gbl/addr offsets, section_size, id)
    [demand data]             ← locals / types / line numbers (demand-loaded)
    [module info]             ← one record per compilation unit
    [global symbol table]     ← one record per exported symbol
    [address info]            ← maps code ranges to modules (for line resolution)

All offsets in the section header are from the start of the section.

Struct reference: bld/watcom/h/wdbginfo.h in the Open Watcom v2 source tree.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path


# ── Format constants ──────────────────────────────────────────────────────────

WAT_DBG_SIGNATURE = 0x8386

_MASTER_HDR_SIZE  = 14   # sizeof(master_dbg_header)
_SECTION_HDR_SIZE = 18   # sizeof(section_dbg_header): 4+4+4+4+2

# demand_kind indices (MAX_DMND = 3)
_DMND_LOCALS = 0
_DMND_TYPES  = 1
_DMND_LINES  = 2

# GBL_KIND_* flags
_GBL_KIND_STATIC = 0x01
_GBL_KIND_DATA   = 0x02
_GBL_KIND_CODE   = 0x04

# SEG_COUNT_MASK
_SEG_COUNT_MASK = 0x7FFF


# ── Exceptions ────────────────────────────────────────────────────────────────

class WatcomDebugNotFoundError(ValueError):
    """Raised when the data does not end with a valid Watcom debug header."""


# ── Public data classes ───────────────────────────────────────────────────────

@dataclass
class WatcomSymbol:
    """One entry from the global symbol table."""

    raw_name: str
    """Mangled name as stored in the debug info (e.g. ``add_``, ``_answer``)."""

    name: str
    """Demangled display name (e.g. ``add``, ``answer``)."""

    segment: int
    """1-based LE object index (1 = code, 2 = data)."""

    offset: int
    """Byte offset within the LE object."""

    module_index: int
    """0-based index into :attr:`WatcomDebugInfo.modules`."""

    is_code: bool
    is_data: bool
    is_static: bool
    calling_convention: str | None
    """``'__watcall'`` for code symbols with the default trailing-underscore
    decoration; ``None`` for data symbols and undecorated names."""


@dataclass
class WatcomModule:
    """One compilation unit record from the module info section."""

    index: int
    """0-based position in the modules list."""

    name: str
    """Full source path as recorded by the compiler."""

    language: str
    """Language string from the source language table (e.g. ``'c'``)."""


@dataclass
class WatcomLineEntry:
    """One source-line-to-code-offset mapping."""

    line: int
    """Source line number."""

    module_index: int
    """0-based index into :attr:`WatcomDebugInfo.modules`."""

    code_offset: int
    """Absolute flat byte offset into the code object (object 1)."""


@dataclass
class WatcomDebugInfo:
    """Complete parsed Watcom Debug Info 3.0 section."""

    modules: list[WatcomModule]
    symbols: list[WatcomSymbol]
    line_numbers: list[WatcomLineEntry]
    """All line entries across all modules, sorted by code_offset."""


# ── Name demangling ───────────────────────────────────────────────────────────

def _demangle(raw: str, is_code: bool) -> tuple[str, str | None]:
    """Reverse the x86 Watcom name decoration.

    Default __watcall convention (bld/comp_cfg/h/langenv.h):
      - Code: ``TS_CODE_MANGLE = "*_"``  → trailing underscore
      - Data: ``TS_DATA_MANGLE = "_*"``  → leading underscore

    Returns (display_name, calling_convention).
    """
    if is_code and len(raw) > 1 and raw.endswith("_"):
        return raw[:-1], "__watcall"
    if not is_code and len(raw) > 1 and raw.startswith("_"):
        return raw[1:], None
    return raw, None


# ── Internal parsing helpers ──────────────────────────────────────────────────

def _read_length_prefixed(data: bytes, pos: int) -> tuple[str, int]:
    """Read a Pascal-style length-prefixed ASCII string.  Returns (string, new_pos)."""
    length = data[pos]
    name = data[pos + 1 : pos + 1 + length].decode("ascii", errors="replace")
    return name, pos + 1 + length


def _parse_language_table(data: bytes, start: int, size: int) -> list[str]:
    """Parse the null-terminated language name strings."""
    languages: list[str] = []
    pos = start
    end = start + size
    while pos < end:
        nul = data.index(b"\x00", pos, end)
        lang = data[pos:nul].decode("ascii", errors="replace")
        if lang:
            languages.append(lang)
        pos = nul + 1
    return languages


def _parse_modules(
    data: bytes,
    section_start: int,
    mod_offset: int,
    gbl_offset: int,
    lang_data: bytes,
) -> list[WatcomModule]:
    """Parse module info records (permanently-loaded section)."""
    modules: list[WatcomModule] = []
    pos = section_start + mod_offset
    end = section_start + gbl_offset
    idx = 0

    while pos < end:
        lang_off, = struct.unpack_from("<H", data, pos); pos += 2

        # Three demand_info entries: locals, types, lines
        # Each is info_off(4) + entries(2) = 6 bytes
        pos += 18  # skip 3 × demand_info; we use lines_offset from a separate pass

        name, pos = _read_length_prefixed(data, pos)

        # Resolve language string from table
        if lang_off < len(lang_data):
            nul = lang_data.index(b"\x00", lang_off) if b"\x00" in lang_data[lang_off:] else len(lang_data)
            language = lang_data[lang_off:nul].decode("ascii", errors="replace")
        else:
            language = ""

        modules.append(WatcomModule(index=idx, name=name, language=language))
        idx += 1

    return modules


def _parse_module_demand_info(
    data: bytes,
    section_start: int,
    mod_offset: int,
    gbl_offset: int,
) -> list[tuple[int, int]]:
    """Return (lines_info_off, lines_entries) for each module.

    This is a second pass over the module records to extract the demand_info
    for line numbers (DMND_LINES = index 2).
    """
    result: list[tuple[int, int]] = []
    pos = section_start + mod_offset
    end = section_start + gbl_offset

    while pos < end:
        pos += 2  # language offset
        for demand_idx in range(3):
            info_off, entries = struct.unpack_from("<IH", data, pos); pos += 6
            if demand_idx == _DMND_LINES:
                result.append((info_off, entries))
        name_len = data[pos]; pos += 1 + name_len

    return result


def _parse_symbols(
    data: bytes,
    section_start: int,
    gbl_offset: int,
    addr_offset: int,
) -> list[WatcomSymbol]:
    """Parse v3 global symbol records."""
    symbols: list[WatcomSymbol] = []
    pos = section_start + gbl_offset
    end = section_start + addr_offset

    while pos < end:
        # v3_gbl_info: addr48_ptr{offset(4)+segment(2)} + mod(2) + kind(1) + name[1]
        offset, segment, mod_index, kind = struct.unpack_from("<IHHB", data, pos)
        pos += 9
        raw_name, pos = _read_length_prefixed(data, pos)

        is_code   = bool(kind & _GBL_KIND_CODE)
        is_data   = bool(kind & _GBL_KIND_DATA)
        is_static = bool(kind & _GBL_KIND_STATIC)
        name, conv = _demangle(raw_name, is_code)

        symbols.append(WatcomSymbol(
            raw_name=raw_name,
            name=name,
            segment=segment,
            offset=offset,
            module_index=mod_index,
            is_code=is_code,
            is_data=is_data,
            is_static=is_static,
            calling_convention=conv,
        ))

    return symbols


def _build_addr_base_map(
    data: bytes,
    section_start: int,
    addr_offset: int,
    sect_sz: int,
) -> dict[int, int]:
    """Build a map from byte-offset-within-addr-info-section to cumulative flat code offset.

    Line segment records store an ``addr_info_off`` which is a byte offset into the
    address info section pointing at a specific ``addr_dbg_info`` entry.  Walking to
    that entry and accumulating the sizes of all preceding entries in the same block
    gives the base flat code offset for that module's code range.

    Only code-segment (seg == 1) blocks contribute to line number offsets.
    """
    base_map: dict[int, int] = {}
    addr_abs = section_start + addr_offset
    pos = addr_abs
    end = section_start + sect_sz

    while pos + _SECTION_HDR_SIZE <= end:
        if pos + 8 > end:
            break
        base_offset, base_seg, raw_count = struct.unpack_from("<IHH", data, pos)
        count = raw_count & _SEG_COUNT_MASK
        header_end = pos + 8

        if base_seg == 1:
            # byte offset of first entry within the addr info section
            entry_byte_off = header_end - addr_abs
            cumulative = base_offset
            for _ in range(count):
                if header_end + (entry_byte_off - (header_end - addr_abs)) + 6 > end + addr_abs:
                    break
                base_map[entry_byte_off] = cumulative
                sz, = struct.unpack_from("<I", data, addr_abs + entry_byte_off)
                cumulative += sz
                entry_byte_off += 6

        pos = header_end + count * 6

    return base_map


def _parse_line_numbers(
    data: bytes,
    section_start: int,
    demand_info: list[tuple[int, int]],
    addr_base_map: dict[int, int],
) -> list[WatcomLineEntry]:
    """Parse v3 line number records for all modules and resolve flat code offsets."""
    entries: list[WatcomLineEntry] = []

    for mod_idx, (lines_off, lines_entries) in enumerate(demand_info):
        if lines_entries == 0:
            continue

        # The link table has (lines_entries + 1) × uint32 entries, each an offset
        # from section_start to the start of that line segment.
        link_table_abs = section_start + lines_off
        seg_offsets = [
            struct.unpack_from("<I", data, link_table_abs + i * 4)[0]
            for i in range(lines_entries + 1)
        ]

        for seg_idx in range(lines_entries):
            seg_abs = section_start + seg_offsets[seg_idx]

            # v3_line_segment: segment/addr_info_off(4) + count(2)
            addr_info_off, count = struct.unpack_from("<IH", data, seg_abs)
            base = addr_base_map.get(addr_info_off, 0)

            for j in range(count):
                # line_dbg_info: line(2) + code_offset(4)
                line, code_off = struct.unpack_from("<HI", data, seg_abs + 6 + j * 6)
                entries.append(WatcomLineEntry(
                    line=line,
                    module_index=mod_idx,
                    code_offset=base + code_off,
                ))

    entries.sort(key=lambda e: e.code_offset)
    return entries


# ── Public entry point ────────────────────────────────────────────────────────

def parse_watcom_debug(data: bytes) -> WatcomDebugInfo:
    """Parse Watcom Debug Info 3.0 from the raw bytes of a DOS/4GW LE executable.

    The debug section is appended after the LE data pages.  Its location is found
    by reading the master debug header at the very end of the file.

    Raises :exc:`WatcomDebugNotFoundError` if the file does not end with a valid
    Watcom debug header (signature 0x8386).
    """
    file_size = len(data)

    if file_size < _MASTER_HDR_SIZE:
        raise WatcomDebugNotFoundError("File too small to contain Watcom debug info")

    # Master debug header: last 14 bytes
    mh = data[-_MASTER_HDR_SIZE:]
    sig, = struct.unpack_from("<H", mh, 0)
    if sig != WAT_DBG_SIGNATURE:
        raise WatcomDebugNotFoundError(
            f"Watcom debug signature not found: got 0x{sig:04X}, expected 0x{WAT_DBG_SIGNATURE:04X}"
        )

    exe_major = mh[2]
    lang_size, seg_size = struct.unpack_from("<HH", mh, 6)
    debug_size, = struct.unpack_from("<I", mh, 10)

    if exe_major < 3:
        raise WatcomDebugNotFoundError(
            f"Only Watcom debug format v3 is supported; got v{exe_major}"
        )

    debug_start = file_size - debug_size
    if debug_start < 0:
        raise WatcomDebugNotFoundError("debug_size exceeds file size")

    # Language table: null-terminated strings
    lang_data = data[debug_start : debug_start + lang_size]

    # Segment table: skipped (selector values, not needed for 32-bit flat LE)

    # Section header: 18 bytes
    section_start = debug_start + lang_size + seg_size
    if section_start + _SECTION_HDR_SIZE > file_size:
        raise WatcomDebugNotFoundError("Section header exceeds file bounds")

    mod_off, gbl_off, addr_off, sect_sz, _sect_id = struct.unpack_from(
        "<4IH", data, section_start
    )

    # Parse permanently-loaded section data
    modules = _parse_modules(data, section_start, mod_off, gbl_off, lang_data)
    symbols = _parse_symbols(data, section_start, gbl_off, addr_off)

    # Build address→base map for line number resolution
    addr_base_map = _build_addr_base_map(data, section_start, addr_off, sect_sz)

    # Parse demand-loaded line numbers
    demand_info = _parse_module_demand_info(data, section_start, mod_off, gbl_off)
    line_numbers = _parse_line_numbers(data, section_start, demand_info, addr_base_map)

    return WatcomDebugInfo(
        modules=modules,
        symbols=symbols,
        line_numbers=line_numbers,
    )


def parse_watcom_debug_file(filepath: Path) -> WatcomDebugInfo:
    """Convenience wrapper: read a file and parse its Watcom debug info."""
    return parse_watcom_debug(filepath.read_bytes())
