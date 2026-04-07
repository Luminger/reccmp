"""Part of the core analysis/comparison logic of `reccmp`.
These functions load the entity and type databases with information from code annotations and PDB files.
"""

import logging
import re
from pathlib import PureWindowsPath
from typing import Iterable
from collections.abc import Sequence
from reccmp.formats.exceptions import (
    InvalidStringError,
)
from reccmp.formats import Image, PEImage, TextFile
from reccmp.formats.lx import LXImage
from reccmp.formats.watcom_debug import WatcomDebugInfo
from reccmp.cvdump import CvdumpTypesParser, CvdumpAnalysis
from reccmp.parser import DecompCodebase
from reccmp.types import EntityType, ImageId
from reccmp.compare.event import (
    ReccmpEvent,
    ReccmpReportProtocol,
    reccmp_report_nop,
)
from .csv import ReccmpCsvParserError, ReccmpCsvFatalParserError, csv_parse

_MAP_SYMBOL_RE = re.compile(r"^([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})[*+]?\s+(\S+)")
from .db import EntityDb, entity_name_from_string
from .lines import LinesDb

logger = logging.getLogger(__name__)


def load_cvdump_types(cvdump_analysis: CvdumpAnalysis, types: CvdumpTypesParser):
    # TODO: Populate the universal type database here when this exists. (#106)
    # For now, just copy the keys into another CvdumpTypesParser so we can use its API.
    types.keys.update(cvdump_analysis.types.keys)
    types.alerted_types = cvdump_analysis.types.alerted_types


def load_cvdump(cvdump_analysis: CvdumpAnalysis, db: EntityDb, recomp_bin: PEImage):
    # Build the list of entries to insert to the DB.
    # In the rare case we have duplicate symbols for an address, ignore them.
    seen_addrs = set()

    with db.batch() as batch:
        for sym in cvdump_analysis.nodes:
            # Skip nodes where we have almost no information.
            # These probably came from SECTION CONTRIBUTIONS.
            if sym.name() is None and sym.node_type is None:
                continue

            # The PDB might contain sections that do not line up with the
            # actual binary. The symbol "__except_list" is one example.
            # In these cases, just skip this symbol and move on because
            # we can't do much with it.
            if not recomp_bin.is_valid_section(sym.section):
                continue

            addr = recomp_bin.get_abs_addr(sym.section, sym.offset)
            sym.addr = addr

            if addr in seen_addrs:
                continue

            seen_addrs.add(addr)

            # If this symbol is the final one in its section, we were not able to
            # estimate its size because we didn't have the total size of that section.
            # We can get this estimate now and assume that the final symbol occupies
            # the remainder of the section.
            if sym.estimated_size is None:
                sym.estimated_size = (
                    recomp_bin.get_section_extent_by_index(sym.section) - sym.offset
                )

            if sym.node_type in (EntityType.STRING, EntityType.WIDECHAR):
                # Use the section contribution size if we have it. It is more accurate
                # than the number embedded in the string symbol:
                #
                #     e.g. ??_C@_0BA@EFDM@MxObjectFactory?$AA@
                #     text: "MxObjectFactory"
                #     reported length: 16 (includes null terminator)
                #
                #     c.f. ??_C@_03DPKJ@enz?$AA@
                #     text: "enz"
                #     reported length: 3 (does NOT include terminator)
                #
                # Using a known length enables us to read strings that include null bytes.
                # If section contribution is null, and no other data source sets the size,
                # the string reading function will read until it hits the null-terminator.

                batch.set(
                    ImageId.RECOMP,
                    addr,
                    type=sym.node_type,
                    symbol=sym.decorated_name,
                    size=sym.section_contribution,
                )

            elif sym.node_type == EntityType.FLOAT:
                # Leave the entity name blank to start. (Don't use the symbol.)
                # We will read the float's value from the binary.
                batch.set(
                    ImageId.RECOMP,
                    addr,
                    type=sym.node_type,
                    symbol=sym.decorated_name,
                    size=sym.size(),
                )
            else:
                # Non-string entities.
                batch.set(
                    ImageId.RECOMP,
                    addr,
                    type=sym.node_type,
                    name=sym.name(),
                    symbol=sym.decorated_name,
                    size=sym.size(),
                )

                # Set the cvdump type key so it can be referenced later.
                if sym.node_type == EntityType.DATA and sym.data_type is not None:
                    assert isinstance(sym.data_type.key, int)
                    batch.set(ImageId.RECOMP, addr, data_type=sym.data_type.key)


def load_cvdump_lines(
    cvdump_analysis: CvdumpAnalysis, lines_db: LinesDb, recomp_bin: PEImage
):
    for filename, values in cvdump_analysis.lines.items():
        lines = [
            (v.line_number, recomp_bin.get_abs_addr(v.section, v.offset))
            for v in values
        ]
        lines_db.add_lines(filename, lines)

    # The seen_addrs set has more than functions, but the intersection of
    # these addrs and the code lines should be just the functions.
    seen_addrs = set(
        # TODO: Ideally this conversion and filtering would happen inside CvdumpAnalysis.
        recomp_bin.get_abs_addr(node.section, node.offset)
        for node in cvdump_analysis.nodes
        if recomp_bin.is_valid_section(node.section)
    )

    lines_db.mark_function_starts(tuple(seen_addrs))


# pylint: disable=too-many-positional-arguments
def load_markers(
    code_files: Sequence[TextFile],
    lines_db: LinesDb,
    orig_bin: Image,
    target_id: str,
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
):
    lines_db.add_local_paths((f.path for f in code_files))
    codebase = DecompCodebase(code_files, target_id)

    # If the address of any annotation would cause an exception,
    # remove it and report an error.
    bad_annotations = codebase.prune_invalid_addrs(orig_bin.is_valid_vaddr)

    for sym in bad_annotations:
        report(
            ReccmpEvent.INVALID_USER_DATA,
            sym.offset,
            msg=f"Invalid address 0x{sym.offset:x} on {sym.type.name} annotation in file: {sym.filename}",
        )

    # Make sure each address is used only once
    duplicate_annotations = codebase.prune_reused_addrs()

    for sym in duplicate_annotations:
        report(
            ReccmpEvent.INVALID_USER_DATA,
            sym.offset,
            msg=f"Dropped duplicate address 0x{sym.offset:x} on {sym.type.name} annotation in file: {sym.filename}",
        )

    # Match lineref functions first because this is a guaranteed match.
    # If we have two functions that share the same name, and one is
    # a lineref, we can match the nameref correctly because the lineref
    # was already removed from consideration.
    with db.batch() as batch:
        for fun in codebase.iter_line_functions():
            batch.set(
                ImageId.ORIG,
                fun.offset,
                type=EntityType.FUNCTION,
                stub=fun.should_skip(),
            )

            assert fun.filename is not None
            recomp_addr = lines_db.find_function(
                fun.filename, fun.line_number, fun.end_line
            )

            if recomp_addr is not None:
                batch.match(fun.offset, recomp_addr)

        for fun in codebase.iter_name_functions():
            batch.set(
                ImageId.ORIG,
                fun.offset,
                type=EntityType.FUNCTION,
                stub=fun.should_skip(),
                library=fun.is_library(),
            )

            if fun.name.startswith("?") or fun.name_is_symbol:
                batch.set(ImageId.ORIG, fun.offset, symbol=fun.name)
            else:
                batch.set(ImageId.ORIG, fun.offset, name=fun.name)

        for var in codebase.iter_variables():
            batch.set(ImageId.ORIG, var.offset, name=var.name, type=EntityType.DATA)
            if var.is_static and var.parent_function is not None:
                batch.set(
                    ImageId.ORIG,
                    var.offset,
                    static_var=True,
                    parent_function=var.parent_function,
                )

        for tbl in codebase.iter_vtables():
            batch.set(
                ImageId.ORIG,
                tbl.offset,
                name=tbl.name,
                base_class=tbl.base_class,
                type=EntityType.VTABLE,
            )

        for string in codebase.iter_strings():
            # Not that we don't trust you, but we're checking the string
            # annotation to make sure it is accurate.
            try:
                if string.is_widechar:
                    string_size = 2 * len(string.name) + 2
                    raw = orig_bin.read(string.offset, string_size)
                    orig = raw.decode("utf-16-le")
                else:
                    string_size = len(string.name) + 1
                    raw = orig_bin.read(string.offset, string_size)
                    orig = raw.decode("latin1")

                string_correct = orig[-1] == "\0" and string.name == orig[:-1]

            except InvalidStringError:
                logger.warning(
                    "Could not read string from orig 0x%x, wide=%s",
                    string.offset,
                    string.is_widechar,
                )
                string_correct = False

            except UnicodeDecodeError:
                logger.warning(
                    "Could not decode string: %s, wide=%s",
                    raw,
                    string.is_widechar,
                )
                string_correct = False

            if not string_correct:
                report(
                    ReccmpEvent.INVALID_USER_DATA,
                    string.offset,
                    msg=f"Data at 0x{string.offset:x} does not match string {repr(string.name)}",
                )
                continue

            batch.set(
                ImageId.ORIG,
                string.offset,
                name=entity_name_from_string(string.name, wide=string.is_widechar),
                type=EntityType.STRING,
                size=string_size,
                verified=True,
            )

        for line in codebase.iter_line_symbols():
            batch.set(
                ImageId.ORIG,
                line.offset,
                name=line.name,
                filename=str(line.filename),
                line=line.line_number,
                type=EntityType.LINE,
            )


def load_data_sources(db: EntityDb, data_sources: Iterable[TextFile]):
    for ds_file in data_sources:
        if ds_file.path.suffix.lower() == ".csv":
            load_csv(db, ds_file)
        else:
            logger.error(
                "Skipped data source file '%s'. If this is csv, please add the extension.",
                ds_file.path,
            )


def load_csv(db: EntityDb, csv_file: TextFile):
    rows = []

    try:
        rowgen = csv_parse(csv_file.text)
        while True:
            try:
                rows.append(next(rowgen))
            except StopIteration:
                break
            except ReccmpCsvParserError as ex:
                logger.error(
                    "In csv file %s: %s",
                    str(csv_file.path),
                    str(ex),
                )
                continue

    except ReccmpCsvFatalParserError as ex:
        logger.error(
            "Failed to parse csv file %s (%s)",
            str(csv_file.path),
            ex.__class__.__name__,
        )
        return

    with db.batch() as batch:
        for addr, values in rows:
            batch.set(ImageId.ORIG, addr, **values)


# ── Watcom / LE ingestion ─────────────────────────────────────────────────────


def load_watcom_debug(
    debug_info: WatcomDebugInfo,
    db: EntityDb,
    bin: LXImage,
    image_id: ImageId,
) -> None:
    """Populate EntityDb from Watcom Debug Info 3.0.

    Computes symbol virtual addresses from the LE object table stored in
    *bin*.  Function sizes are estimated from the gap to the next symbol
    within the same segment; the final symbol in each segment gets the
    remainder of that segment's virtual size.
    """
    if not debug_info.symbols:
        return

    # Group symbols by segment so we can compute sizes within each segment.
    from collections import defaultdict
    by_seg: dict[int, list] = defaultdict(list)
    for sym in debug_info.symbols:
        by_seg[sym.segment].append(sym)

    for seg_syms in by_seg.values():
        seg_syms.sort(key=lambda s: s.offset)

    with db.batch() as batch:
        for seg, seg_syms in by_seg.items():
            idx = seg - 1
            if idx < 0 or idx >= len(bin.sections):
                continue
            section = bin.sections[idx]
            seg_vsize = section.virtual_size
            seg_base = section.virtual_address

            for i, sym in enumerate(seg_syms):
                addr = seg_base + sym.offset

                # Size: gap to next symbol in this segment, or remainder
                if i + 1 < len(seg_syms):
                    size = seg_syms[i + 1].offset - sym.offset
                else:
                    size = seg_vsize - sym.offset

                entity_type = EntityType.FUNCTION if sym.is_code else EntityType.DATA

                batch.set(
                    image_id,
                    addr,
                    type=entity_type,
                    name=sym.name,
                    symbol=sym.raw_name,
                    size=size,
                )


def load_watcom_lines(
    debug_info: WatcomDebugInfo,
    lines_db: LinesDb,
    bin: LXImage,
) -> None:
    """Populate LinesDb from Watcom Debug Info 3.0 line number tables.

    Line entries are grouped by source module and added to *lines_db* using
    the module's recorded path as the foreign path key.  The code segment
    base address from *bin* is used to convert flat code offsets to virtual
    addresses.

    Function starts are marked using the virtual addresses of all code symbols,
    mirroring what :func:`load_cvdump_lines` does with PDB data.
    """
    if not bin.sections:
        return

    code_base = bin.sections[0].virtual_address  # segment 1 = index 0

    # Group line entries by module index
    from collections import defaultdict
    by_module: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for entry in debug_info.line_numbers:
        va = code_base + entry.code_offset
        by_module[entry.module_index].append((entry.line, va))

    for mod_idx, lines in by_module.items():
        if mod_idx >= len(debug_info.modules):
            continue
        module = debug_info.modules[mod_idx]
        # Wrap the recorded path as a PureWindowsPath — LinesDb matches by
        # filename (.name) so the path style doesn't matter for the lookup.
        foreign_path = PureWindowsPath(module.name)
        lines_db.add_lines(foreign_path, lines)

    # Mark function starts using code symbol addresses so that find_function()
    # can identify the entry point of each annotated function.
    code_sym_addrs = [
        bin.sections[sym.segment - 1].virtual_address + sym.offset
        for sym in debug_info.symbols
        if sym.is_code and 0 < sym.segment <= len(bin.sections)
    ]
    lines_db.mark_function_starts(code_sym_addrs)


def load_watcom_map(
    map_content: str,
    db: EntityDb,
    section_bases: dict[int, int],
    image_id: ImageId,
) -> None:
    """Populate EntityDb from a wlink-generated .map file.

    *section_bases* maps 1-based LE segment numbers to their base virtual
    addresses (e.g. ``{1: 0x10000, 2: 0x20000}``).  Only segments present
    in this dict are loaded.

    This is a lightweight alternative to :func:`load_watcom_debug` for
    cases where a full debug build is not available.  It provides symbol
    names and addresses but no sizes.

    Map file symbol lines have the form::

        SSSS:OOOOOOOO[*+]  symbol_name
    """
    with db.batch() as batch:
        for line in map_content.splitlines():
            m = _MAP_SYMBOL_RE.match(line)
            if m is None:
                continue
            seg = int(m.group(1), 16)
            offset = int(m.group(2), 16)
            name = m.group(3)

            if seg not in section_bases:
                continue

            addr = section_bases[seg] + offset
            entity_type = EntityType.FUNCTION if seg == 1 else EntityType.DATA

            batch.set(image_id, addr, type=entity_type, symbol=name)


def match_watcom_symbols(db: EntityDb) -> None:
    """Match ORIG and RECOMP entities by their raw Watcom mangled symbol name.

    Watcom preserves mangled names identically in the debug info and the
    linker map file, so a direct string equality match is sufficient.

    This is the Watcom equivalent of :func:`reccmp.compare.match_msvc.match_symbols`
    (without the 255-character MSVC truncation).
    """
    # Build a lookup from symbol name -> recomp_addr for unmatched recomp entities
    recomp_by_symbol: dict[str, int] = {}
    for recomp_addr, symbol in db.sql.execute(
        """SELECT recomp_addr, json_extract(kvstore, '$.symbol') as symbol
           FROM recomp_unmatched WHERE symbol IS NOT NULL"""
    ):
        # Only take the first occurrence of each symbol (duplicates are skipped)
        recomp_by_symbol.setdefault(symbol, recomp_addr)

    with db.batch() as batch:
        for orig_addr, symbol in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.symbol') as symbol
               FROM orig_unmatched WHERE symbol IS NOT NULL"""
        ):
            if symbol in recomp_by_symbol:
                batch.match(orig_addr, recomp_by_symbol.pop(symbol))
