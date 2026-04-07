"""
LE (Linear Executable) image support.

Based on the following resources:
- LX - Linear eXecutable Module Format Description
  http://www.edm2.com/index.php/LX_-_Linear_eXecutable_Module_Format_Description
- Open Watcom v2: bld/watcom/h/exeflat.h  (LE/LX header and fixup constants)
- Open Watcom v2: bld/exedump/c/wdfix.c   (fixup record parsing reference)

### File layout variants

Plain DOS/4GW (freeware, the common case):
    [MZ header]  e_lfanew ──► [LE header]  [data pages]

detect_image() handles this directly: it reads `data[mz_header.e_lfanew : +2]`,
finds b'LE', and calls LXImage.from_memory() with the default mz_offset=0.

DOS/4GW Professional (commercial, e.g. Caesar II):
    [outer MZ]  e_lfanew ──► [BW stub #1]
                              next_header_pos ──► [BW stub #2]
                                                   next_header_pos ──► [inner MZ]
                                                                         e_lfanew ──► [LE header]

detect_image() sees b'BW' at the outer MZ's e_lfanew and returns a plain MZImage.
The caller is responsible for walking the BW chain to the inner MZ and then calling
LXImage.from_memory(data, inner_mz, filepath, mz_offset=inner_mz_offset).

### Field naming note

LXImageHeader.page_offset_shift is named for the LX format variant.  In LE files
(magic b'LE') the same struct field stores last_page_size: the number of valid bytes
in the final page of the binary, not a shift count.  The property LXImage.last_page_size
exposes this under the correct name.
"""

import struct
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Iterator

from .exceptions import InvalidVirtualAddressError
from .image import Image, ImageImport, ImageRegion, ImageSection, ImageSectionFlags
from .mz import ImageDosHeader


class LXHeaderNotFoundError(ValueError):
    pass


# ── LE object flags (exeflat.h OBJ_* constants) ──────────────────────────────

_OBJ_READABLE   = 0x0001
_OBJ_WRITEABLE  = 0x0002
_OBJ_EXECUTABLE = 0x0004
_OBJ_ZEROED     = 0x0100  # uninitialised (BSS) pages


# ── LE fixup record constants (exeflat.h OSF_* constants) ────────────────────

# Source type (low nibble of first fixup byte)
_OSF_SOURCE_MASK    = 0x0F
_OSF_SOURCE_SEG     = 0x02  # 16-bit segment selector
_OSF_SOURCE_OFF_32  = 0x07  # 32-bit flat offset  ← the only kind we track
_OSF_SFLAG_LIST     = 0x20  # source-offset list follows

# Target type (low 2 bits of second fixup byte)
_OSF_TARGET_MASK          = 0x03
_OSF_TARGET_INTERNAL      = 0x00  # internal reference (within this module)
_OSF_TARGET_EXT_ORD       = 0x01  # import by ordinal
_OSF_TARGET_EXT_NAME      = 0x02  # import by name
_OSF_TARGET_INT_VIA_ENTRY = 0x03  # internal via entry table

# Target modifier flags (upper bits of second fixup byte)
_OSF_TFLAG_ADDITIVE_VAL  = 0x04
_OSF_TFLAG_OFF_32BIT     = 0x10  # target offset is 32 bits (else 16)
_OSF_TFLAG_ADD_32BIT     = 0x20  # additive value is 32 bits (else 16)
_OSF_TFLAG_OBJ_MOD_16BIT = 0x40  # object/module number is 16 bits (else 8)
_OSF_TFLAG_ORDINAL_8BIT  = 0x80  # ordinal is 8 bits (else 16)


# ── LXImageHeader ─────────────────────────────────────────────────────────────

# pylint: disable=too-many-instance-attributes
@dataclass(frozen=True)
class LXImageHeader:
    magic: bytes
    byte_ordering: int
    word_ordering: int
    format_level: int
    cpu_type: int
    os_type: int
    module_version: int
    module_flags: int
    module_number_of_pages: int
    eip_object_nb: int
    eip: int
    esp_object_nb: int
    esp: int
    page_size: int
    page_offset_shift: int   # LE: last_page_size; LX: page-offset shift count
    fixup_section_size: int
    fixup_section_checksum: int
    loader_section_size: int
    loader_section_checksum: int
    object_table_off: int
    nb_objects_in_module: int
    object_page_table_offset: int
    object_iter_pages_off: int
    resource_table_off: int
    nb_resource_table_entries: int
    resident_name_table_offset: int
    entry_table_offset: int
    module_directives_offset: int
    nb_module_directives: int
    fixup_page_table_offset: int
    fixup_record_table_offset: int
    import_module_table_offset: int
    nb_import_module_entries: int
    import_procedure_table_offset: int
    per_page_checksum_offset: int
    data_pages_offset: int
    nb_preload_pages: int
    non_resident_name_table_offset: int
    non_resident_name_table_length: int
    non_resident_name_table_checksum: int
    auto_ds_object_nb: int
    debug_info_offset: int
    debug_info_len: int
    nb_instance_preload: int
    nb_instance_demand: int
    heap_size: int

    @classmethod
    def from_memory(cls, data: bytes, offset: int) -> tuple["LXImageHeader", int]:
        if not cls.taste(data, offset):
            raise LXHeaderNotFoundError
        if data[offset + 2] != 0 or data[offset + 3] != 0:
            raise NotImplementedError("Big-endian LX not implemented")
        struct_fmt = "<2s2BI2H40I"
        items = struct.unpack_from(struct_fmt, data, offset)
        return cls(*items), offset + struct.calcsize(struct_fmt)

    @classmethod
    def taste(cls, data: bytes, offset: int) -> bool:
        return data[offset : offset + 2] == b"LE"


# ── Object table parsing ──────────────────────────────────────────────────────

def _le_obj_flags(raw_flags: int) -> ImageSectionFlags:
    """Map raw LE object flags to ImageSectionFlags."""
    flags = ImageSectionFlags(0)
    if raw_flags & _OBJ_READABLE:
        flags |= ImageSectionFlags.READ
    if raw_flags & _OBJ_WRITEABLE:
        flags |= ImageSectionFlags.WRITE
    if raw_flags & _OBJ_EXECUTABLE:
        flags |= ImageSectionFlags.EXECUTE
    if raw_flags & _OBJ_ZEROED:
        flags |= ImageSectionFlags.BSS
    return flags


def _parse_le_objects(
    data: bytes,
    header: LXImageHeader,
    le_offset: int,
    mz_offset: int,
) -> tuple[tuple[ImageSection, ...], list[tuple[int, int, int, int]]]:
    """Parse the LE object table and return (sections, raw_objects).

    raw_objects is a list of (reloc_base, page_table_index, num_pages, virtual_size)
    tuples, one per object, retained for fixup VA computation.

    In the LE format, data_pages_offset is relative to the start of the MZ stub
    (i.e. from mz_offset, not from the LE header itself).  The absolute file offset
    of the first data page is therefore mz_offset + header.data_pages_offset.
    """
    data_pages_abs = mz_offset + header.data_pages_offset
    last_page_size = header.page_offset_shift  # see module docstring
    total_pages    = header.module_number_of_pages
    page_size      = header.page_size

    sections: list[ImageSection] = []
    raw_objects: list[tuple[int, int, int, int]] = []

    obj_table_abs = le_offset + header.object_table_off

    for i in range(header.nb_objects_in_module):
        off = obj_table_abs + i * 24
        vsize, reloc_base, raw_flags, ptidx, npages, _ = struct.unpack_from(
            "<6I", data, off
        )

        # Compute physical file size for this object's pages.
        # The very last page in the binary (page_table_index + num_pages - 1 == total_pages)
        # may be shorter than a full page; its size is last_page_size.
        if npages == 0:
            file_size = 0
        else:
            last_page_idx = ptidx + npages - 1
            if last_page_idx == total_pages:
                file_size = (npages - 1) * page_size + last_page_size
            else:
                file_size = npages * page_size

        file_offset = data_pages_abs + (ptidx - 1) * page_size

        sections.append(ImageSection(
            name=f"obj{i + 1}",
            virtual_range=range(reloc_base, reloc_base + vsize),
            physical_range=range(file_offset, file_offset + file_size),
            view=memoryview(data)[file_offset : file_offset + file_size],
            flags=_le_obj_flags(raw_flags),
        ))
        raw_objects.append((reloc_base, ptidx, npages, vsize))

    return tuple(sections), raw_objects


# ── Fixup record parsing ──────────────────────────────────────────────────────

def _fixup_source_va(
    page_0based: int,
    src_off: int,
    page_size: int,
    raw_objects: list[tuple[int, int, int, int]],
) -> int | None:
    """Return the virtual address of a fixup source location.

    page_0based: zero-based page index within the whole module.
    src_off:     byte offset within that page (may exceed page_size for cross-page
                 fixups, encoded as a signed 16-bit value in the record stream).
    """
    # src_off is read as unsigned 16-bit but can represent a negative offset
    # (cross-page fixup pointing slightly before the nominal page start).
    if src_off > 0x7FFF:
        src_off -= 0x10000

    for reloc_base, ptidx, npages, _ in raw_objects:
        obj_start_page = ptidx - 1          # 0-based start page of this object
        obj_end_page   = obj_start_page + npages  # exclusive
        if obj_start_page <= page_0based < obj_end_page:
            page_within_obj = page_0based - obj_start_page
            return reloc_base + page_within_obj * page_size + src_off
    return None


def _parse_le_fixups(
    data: bytes,
    header: LXImageHeader,
    le_offset: int,
    raw_objects: list[tuple[int, int, int, int]],
) -> tuple[frozenset[int], frozenset[int]]:
    """Parse LE fixup records and return (source_vas, target_vas).

    source_vas: virtual addresses WHERE fixup patches are applied in the image.
    target_vas: virtual addresses that internal off32 fixups point TO.

    Both sets are used by the comparison engine:
    - source_vas  →  LXImage.relocations  (tells ParseAsm where pointers live)
    - target_vas  →  LXImage.is_relocated_addr()  (tells ParseAsm if a value is a ptr)
    """
    fpt_abs = le_offset + header.fixup_page_table_offset
    frt_abs = le_offset + header.fixup_record_table_offset
    num_pages = header.module_number_of_pages
    page_size = header.page_size

    # Read fixup page table: num_pages+1 dwords giving byte offsets into the
    # fixup record table for each page (entries[p] .. entries[p+1] is page p's records).
    page_offsets = [
        struct.unpack_from("<I", data, fpt_abs + i * 4)[0]
        for i in range(num_pages + 1)
    ]

    source_vas: set[int] = set()
    target_vas: set[int] = set()

    for page in range(num_pages):
        pos = frt_abs + page_offsets[page]
        end = frt_abs + page_offsets[page + 1]

        while pos < end:
            source_byte = data[pos]
            flags_byte  = data[pos + 1]
            pos += 2

            src_kind = source_byte & _OSF_SOURCE_MASK
            is_list  = bool(source_byte & _OSF_SFLAG_LIST)

            # Read the single source offset (or prepare for the list below)
            if is_list:
                src_count = data[pos]
                pos += 1
                src_off_single = 0  # unused when is_list
            else:
                src_off_single = struct.unpack_from("<H", data, pos)[0]
                src_count = 0
                pos += 2

            tgt_type = flags_byte & _OSF_TARGET_MASK

            if tgt_type == _OSF_TARGET_INTERNAL:
                pos, tgt_va = _parse_internal_record(
                    data, pos, flags_byte, raw_objects
                )
            elif tgt_type == _OSF_TARGET_EXT_ORD:
                pos = _skip_ext_ord(data, pos, flags_byte, is_list, src_count)
                tgt_va = None
            elif tgt_type == _OSF_TARGET_EXT_NAME:
                pos = _skip_ext_name(data, pos, flags_byte, is_list, src_count)
                tgt_va = None
            elif tgt_type == _OSF_TARGET_INT_VIA_ENTRY:
                pos = _skip_int_via_entry(data, pos, flags_byte, is_list, src_count)
                tgt_va = None
            else:
                # Unknown type: cannot safely advance pos, stop this page.
                break

            # Only off32 internal fixups contribute to our VA sets.
            if src_kind == _OSF_SOURCE_OFF_32 and tgt_va is not None:
                if tgt_va is not None:
                    target_vas.add(tgt_va)

                if is_list:
                    for _ in range(src_count):
                        src_off = struct.unpack_from("<H", data, pos)[0]
                        pos += 2
                        va = _fixup_source_va(page, src_off, page_size, raw_objects)
                        if va is not None:
                            source_vas.add(va)
                else:
                    va = _fixup_source_va(page, src_off_single, page_size, raw_objects)
                    if va is not None:
                        source_vas.add(va)
            elif is_list:
                # Non-off32 list: still need to consume the source-offset list.
                pos += src_count * 2

    return frozenset(source_vas), frozenset(target_vas)


def _parse_internal_record(
    data: bytes,
    pos: int,
    flags: int,
    raw_objects: list[tuple[int, int, int, int]],
) -> tuple[int, int | None]:
    """Parse an internal fixup record body (after the source/flags bytes).

    Returns (new_pos, target_va).  target_va is None when the target object index
    is out of range (shouldn't happen in a well-formed binary).
    """
    # Object number: 16-bit or 8-bit
    if flags & _OSF_TFLAG_OBJ_MOD_16BIT:
        obj_num = struct.unpack_from("<H", data, pos)[0]
        pos += 2
    else:
        obj_num = data[pos]
        pos += 1

    # Target offset (absent only for OSF_SOURCE_SEG; present for all 32-bit offsets)
    tgt_off = 0
    if flags & _OSF_TFLAG_OFF_32BIT:
        tgt_off = struct.unpack_from("<I", data, pos)[0]
        pos += 4
    else:
        tgt_off = struct.unpack_from("<H", data, pos)[0]
        pos += 2

    # Compute target VA from object number (1-based)
    tgt_va: int | None = None
    idx = obj_num - 1
    if 0 <= idx < len(raw_objects):
        reloc_base = raw_objects[idx][0]
        tgt_va = reloc_base + tgt_off

    return pos, tgt_va


def _skip_ext_ord(
    data: bytes, pos: int, flags: int, is_list: bool, count: int
) -> int:
    """Skip an import-by-ordinal fixup record body."""
    # Module number
    pos += 2 if (flags & _OSF_TFLAG_OBJ_MOD_16BIT) else 1
    # Import ordinal
    if flags & _OSF_TFLAG_ORDINAL_8BIT:
        pos += 1
    elif flags & _OSF_TFLAG_OFF_32BIT:
        pos += 4
    else:
        pos += 2
    # Additive value
    if flags & _OSF_TFLAG_ADDITIVE_VAL:
        pos += 4 if (flags & _OSF_TFLAG_ADD_32BIT) else 2
    if is_list:
        pos += count * 2
    return pos


def _skip_ext_name(
    data: bytes, pos: int, flags: int, is_list: bool, count: int
) -> int:
    """Skip an import-by-name fixup record body."""
    # Module number
    pos += 2 if (flags & _OSF_TFLAG_OBJ_MOD_16BIT) else 1
    # Procedure name offset
    pos += 4 if (flags & _OSF_TFLAG_OFF_32BIT) else 2
    # Additive value
    if flags & _OSF_TFLAG_ADDITIVE_VAL:
        pos += 4 if (flags & _OSF_TFLAG_ADD_32BIT) else 2
    if is_list:
        pos += count * 2
    return pos


def _skip_int_via_entry(
    data: bytes, pos: int, flags: int, is_list: bool, count: int
) -> int:
    """Skip an internal-via-entry-table fixup record body."""
    # Entry ordinal
    pos += 2 if (flags & _OSF_TFLAG_OBJ_MOD_16BIT) else 1
    # Additive value
    if flags & _OSF_TFLAG_ADDITIVE_VAL:
        pos += 4 if (flags & _OSF_TFLAG_ADD_32BIT) else 2
    if is_list:
        pos += count * 2
    return pos


# ── LXImage ───────────────────────────────────────────────────────────────────

@dataclass
class LXImage(Image):
    mz_header: ImageDosHeader
    header: LXImageHeader
    le_offset: int
    """Absolute file offset of the LE header within self.data."""
    _raw_objects: list[tuple[int, int, int, int]]
    """Raw object table rows: (reloc_base, page_table_index, num_pages, virtual_size).
    Retained after construction for fixup VA computation."""

    @classmethod
    def from_memory(
        cls,
        data: bytes,
        mz_header: ImageDosHeader,
        filepath: Path,
        mz_offset: int = 0,
    ) -> "LXImage":
        """Construct an LXImage from raw file bytes.

        mz_offset is the position of mz_header within data.  It defaults to 0 for
        plain DOS/4GW executables (where the outer MZ is at the start of the file).

        For DOS/4GW Professional executables the caller must walk the BW chain to
        find the inner MZ, then pass inner_mz_offset here so that data_pages_offset
        (which is relative to the MZ stub, not the LE header) resolves correctly.
        """
        le_offset = mz_offset + mz_header.e_lfanew
        header, _ = LXImageHeader.from_memory(data, le_offset)

        sections, raw_objects = _parse_le_objects(data, header, le_offset, mz_offset)
        section_map = {s.name: s for s in sections if s.name}

        return cls(
            filepath=filepath,
            data=data,
            view=memoryview(data),
            mz_header=mz_header,
            header=header,
            le_offset=le_offset,
            _raw_objects=raw_objects,
            sections=sections,
            section_map=section_map,
        )

    # ── Core interface ────────────────────────────────────────────────────────

    def seek(self, vaddr: int) -> tuple[bytes, int]:
        for section in self.sections:
            if section.contains_vaddr(vaddr):
                offset = vaddr - section.virtual_address
                view = section.view[offset:]
                return bytes(view), section.virtual_size - offset
        raise InvalidVirtualAddressError(
            f"{self.filepath}: virtual address 0x{vaddr:x} not in any LE object"
        )

    @property
    def imagebase(self) -> int:
        """Lowest reloc_base_addr across all objects.

        LE has no single imagebase; this value is used by reccmp's ASM parser as a
        lower-bound threshold when deciding whether an immediate operand could be a
        pointer into the image.
        """
        if not self.sections:
            return 0
        return min(s.virtual_address for s in self.sections)

    @property
    def entry(self) -> int:
        """Absolute virtual address of the module entry point."""
        obj = self.sections[self.header.eip_object_nb - 1]
        return obj.virtual_address + self.header.eip

    @property
    def imports(self) -> Iterator[ImageImport]:
        """LE has no Windows-style IAT; external references live in the fixup table.
        Return an empty iterator — reccmp's import-thunk analysis is skipped for LE."""
        return iter([])

    # ── Relocation / fixup interface ──────────────────────────────────────────

    @cached_property
    def _fixup_sets(self) -> tuple[frozenset[int], frozenset[int]]:
        """Parse all LE fixup records once and return (source_vas, target_vas)."""
        return _parse_le_fixups(
            self.data, self.header, self.le_offset, self._raw_objects
        )

    @cached_property
    def relocations(self) -> frozenset[int]:
        """Virtual addresses WHERE fixup patches are applied in the image.

        Analogous to PEImage.relocations (the .reloc section contents).
        Used by find_float_consts() to distinguish data-referencing FP instructions
        from code that happens to contain the same byte pattern.
        """
        source_vas, _ = self._fixup_sets
        return source_vas

    def is_relocated_addr(self, addr: int) -> bool:
        """Return True if addr is a virtual address that an internal off32 fixup
        points to — i.e. addr is a value that appears as a pointer somewhere in the
        loaded image.

        Analogous to PEImage.is_relocated_addr().  Used by ParseAsm to decide
        whether a large immediate operand value should be replaced with a named
        placeholder rather than left as a literal number.
        """
        _, target_vas = self._fixup_sets
        return addr in target_vas

    # ── Section iteration helpers ─────────────────────────────────────────────

    def get_relative_addr(self, addr: int) -> tuple[int, int]:
        """Return (object_index_0based, offset_within_object) for a virtual address."""
        for i, section in enumerate(self.sections):
            if section.contains_vaddr(addr):
                return (i, addr - section.virtual_address)
        raise InvalidVirtualAddressError(
            f"{self.filepath}: virtual address 0x{addr:x} not in any LE object"
        )

    def get_code_regions(self) -> Iterator[ImageRegion]:
        """Yield ImageRegion for each executable object."""
        for section in self.sections:
            if ImageSectionFlags.EXECUTE in section.flags:
                yield ImageRegion(
                    addr=section.virtual_address,
                    data=bytes(section.view[: section.virtual_size]),
                    size=section.virtual_size,
                )

    def get_data_regions(self) -> Iterator[ImageRegion]:
        """Yield ImageRegion for each writable non-executable object."""
        for section in self.sections:
            if (
                ImageSectionFlags.WRITE in section.flags
                and ImageSectionFlags.EXECUTE not in section.flags
            ):
                yield ImageRegion(
                    addr=section.virtual_address,
                    data=bytes(section.view[: section.virtual_size]),
                    size=section.virtual_size,
                )

    def get_const_regions(self) -> Iterator[ImageRegion]:
        """Yield ImageRegion for each read-only non-executable object.

        Caesar II (and most DOS/4GW titles) have no separate read-only data segment,
        so this typically yields nothing.  The method exists so that analysis passes
        that call get_const_regions() work without special-casing LXImage.
        """
        for section in self.sections:
            if (
                ImageSectionFlags.READ in section.flags
                and ImageSectionFlags.WRITE not in section.flags
                and ImageSectionFlags.EXECUTE not in section.flags
            ):
                yield ImageRegion(
                    addr=section.virtual_address,
                    data=bytes(section.view[: section.virtual_size]),
                    size=section.virtual_size,
                )

    # ── Convenience ──────────────────────────────────────────────────────────

    @property
    def last_page_size(self) -> int:
        """Size in bytes of the final (possibly partial) page.

        In the LE format, LXImageHeader.page_offset_shift stores this value.
        In the LX format, the same field stores a shift count used to compute
        page offsets.  The property name makes the LE semantics explicit.
        """
        return self.header.page_offset_shift
