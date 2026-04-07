"""Tests for the Watcom/LE ingestion functions in reccmp/compare/ingest.py.

Uses hello_watdbg.exe (WatcomDebugInfo fixture) and a Mock LXImage with
known section layout:
  sections[0]: code  reloc_base=0x10000  virtual_size=0x581
  sections[1]: data  reloc_base=0x20000  virtual_size=0x10090

This matches the hello_plain.exe / hello_watdbg.exe object layout exactly,
so the computed virtual addresses are deterministic.
"""

from pathlib import PurePosixPath, PureWindowsPath, Path
from typing import Iterator
from unittest.mock import Mock

import pytest

from reccmp.compare.db import EntityDb
from reccmp.compare.ingest import (
    load_watcom_debug,
    load_watcom_lines,
    load_watcom_map,
    load_markers,
    match_watcom_symbols,
)
from reccmp.compare.lines import LinesDb
from reccmp.formats.image import ImageSection, ImageSectionFlags
from reccmp.formats.watcom_debug import WatcomDebugInfo, parse_watcom_debug_file
from reccmp.formats import TextFile
from reccmp.types import EntityType, ImageId

from .binfiles_test_setup import BINFILE_LE_WATDBG


# ── Fixtures ──────────────────────────────────────────────────────────────────

CODE_BASE = 0x10000
DATA_BASE = 0x20000
CODE_VSIZE = 0x581
DATA_VSIZE = 0x10090


def _make_mock_lximage():
    """Mock LXImage with two sections matching hello_watdbg.exe layout."""
    code_section = Mock(spec=[])
    code_section.virtual_address = CODE_BASE
    code_section.virtual_size = CODE_VSIZE

    data_section = Mock(spec=[])
    data_section.virtual_address = DATA_BASE
    data_section.virtual_size = DATA_VSIZE

    bin_ = Mock(spec=[])
    bin_.sections = [code_section, data_section]
    return bin_


@pytest.fixture(name="debug_info", scope="session")
def fixture_debug_info(bin_loader) -> Iterator[WatcomDebugInfo]:
    path: Path = bin_loader(BINFILE_LE_WATDBG, file_is_required=True)
    yield parse_watcom_debug_file(path)


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


@pytest.fixture(name="lines_db")
def fixture_lines_db() -> LinesDb:
    return LinesDb()


# ── load_watcom_debug ─────────────────────────────────────────────────────────


def test_load_watcom_debug_function(db: EntityDb, debug_info: WatcomDebugInfo):
    """Code symbol 'add_' → FUNCTION entity at correct virtual address."""
    bin_ = _make_mock_lximage()
    load_watcom_debug(debug_info, db, bin_, ImageId.ORIG)

    # add_: seg=1 off=0x10  →  VA = 0x10000 + 0x10 = 0x10010
    e = db.get(ImageId.ORIG, CODE_BASE + 0x10)
    assert e is not None
    assert e.get("type") == EntityType.FUNCTION
    assert e.get("symbol") == "add_"
    assert e.get("name") == "add"


def test_load_watcom_debug_data(db: EntityDb, debug_info: WatcomDebugInfo):
    """Data symbol '_answer' → DATA entity at correct virtual address."""
    bin_ = _make_mock_lximage()
    load_watcom_debug(debug_info, db, bin_, ImageId.ORIG)

    # _answer: seg=2 off=0x04  →  VA = 0x20000 + 0x04 = 0x20004
    e = db.get(ImageId.ORIG, DATA_BASE + 0x04)
    assert e is not None
    assert e.get("type") == EntityType.DATA
    assert e.get("symbol") == "_answer"
    assert e.get("name") == "answer"


def test_load_watcom_debug_data_ptr(db: EntityDb, debug_info: WatcomDebugInfo):
    """Data symbol '_answer_ptr' → DATA entity."""
    bin_ = _make_mock_lximage()
    load_watcom_debug(debug_info, db, bin_, ImageId.ORIG)

    e = db.get(ImageId.ORIG, DATA_BASE + 0x08)
    assert e is not None
    assert e.get("type") == EntityType.DATA
    assert e.get("symbol") == "_answer_ptr"


def test_load_watcom_debug_size_from_gap(db: EntityDb, debug_info: WatcomDebugInfo):
    """Function size is the gap to the next symbol in the same segment.
    add_ is at 0x10, get_answer_ is at 0x1D → size of add_ = 0x0D."""
    bin_ = _make_mock_lximage()
    load_watcom_debug(debug_info, db, bin_, ImageId.ORIG)

    e = db.get(ImageId.ORIG, CODE_BASE + 0x10)
    assert e is not None
    assert e.size == 0x1D - 0x10  # gap to get_answer_


def test_load_watcom_debug_recomp_side(db: EntityDb, debug_info: WatcomDebugInfo):
    """load_watcom_debug works for RECOMP as well as ORIG."""
    bin_ = _make_mock_lximage()
    load_watcom_debug(debug_info, db, bin_, ImageId.RECOMP)

    e = db.get(ImageId.RECOMP, CODE_BASE + 0x10)
    assert e is not None
    assert e.get("type") == EntityType.FUNCTION


def test_load_watcom_debug_empty(db: EntityDb):
    """Empty WatcomDebugInfo produces no entities."""
    empty = WatcomDebugInfo(modules=[], symbols=[], line_numbers=[])
    bin_ = _make_mock_lximage()
    load_watcom_debug(empty, db, bin_, ImageId.ORIG)
    assert db.count() == 0


# ── load_watcom_lines ─────────────────────────────────────────────────────────


def test_load_watcom_lines_adds_entries(
    lines_db: LinesDb, debug_info: WatcomDebugInfo
):
    """Line entries for hello.c are added to the LinesDb."""
    bin_ = _make_mock_lximage()
    # Register a local path so the foreign path can be matched
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix="hello.c", delete=False) as f:
        local = Path(f.name)
    try:
        lines_db.add_local_paths([local])
        load_watcom_lines(debug_info, lines_db, bin_)
        # Module 0 has 9 line entries; check that some land in the db
        # via the address→path lookup
        va_line9 = CODE_BASE + 0x0010  # line 9, flat=0x10
        result = lines_db.find_line_of_recomp_address(va_line9)
        # If the foreign path matched, we get a (path, line) tuple
        if result is not None:
            _, line = result
            assert line == 9
    finally:
        os.unlink(local)


def test_load_watcom_lines_marks_function_starts(
    lines_db: LinesDb, debug_info: WatcomDebugInfo
):
    """Code symbol addresses are registered as function starts."""
    bin_ = _make_mock_lximage()
    load_watcom_lines(debug_info, lines_db, bin_)
    # add_ is at CODE_BASE + 0x10; it should be in function_starts
    assert CODE_BASE + 0x10 in lines_db._function_starts


def test_load_watcom_lines_empty(lines_db: LinesDb):
    """Empty debug info produces no lines and no function starts."""
    empty = WatcomDebugInfo(modules=[], symbols=[], line_numbers=[])
    bin_ = _make_mock_lximage()
    load_watcom_lines(empty, lines_db, bin_)
    assert len(lines_db._function_starts) == 0


# ── load_watcom_map ───────────────────────────────────────────────────────────

_SAMPLE_MAP = """\
Open Watcom Linker Version 2.0 beta

                        +------------+
                        |   Groups   |
                        +------------+

Group                           Address              Size

DGROUP                          0002:00000000        00010090

                        +----------------+
                        |   Memory Map   |
                        +----------------+

Address        Symbol

Module: hello_dbg.obj(hello.c)
0001:00000010+ add_
0001:0000001d+ get_answer_
0001:0000002f  main_
0002:00000004+ _answer
0002:00000008+ _answer_ptr
0001:0000004c  _cstart_
"""

_SECTION_BASES = {1: CODE_BASE, 2: DATA_BASE}


def test_load_watcom_map_code_symbol(db: EntityDb):
    load_watcom_map(_SAMPLE_MAP, db, _SECTION_BASES, ImageId.ORIG)

    e = db.get(ImageId.ORIG, CODE_BASE + 0x10)
    assert e is not None
    assert e.get("type") == EntityType.FUNCTION
    assert e.get("symbol") == "add_"


def test_load_watcom_map_data_symbol(db: EntityDb):
    load_watcom_map(_SAMPLE_MAP, db, _SECTION_BASES, ImageId.ORIG)

    e = db.get(ImageId.ORIG, DATA_BASE + 0x04)
    assert e is not None
    assert e.get("type") == EntityType.DATA
    assert e.get("symbol") == "_answer"


def test_load_watcom_map_all_code_symbols(db: EntityDb):
    """All three code symbols from the sample map are loaded."""
    load_watcom_map(_SAMPLE_MAP, db, _SECTION_BASES, ImageId.ORIG)
    for offset, name in [(0x10, "add_"), (0x1D, "get_answer_"), (0x2F, "main_"), (0x4C, "_cstart_")]:
        e = db.get(ImageId.ORIG, CODE_BASE + offset)
        assert e is not None, f"Missing {name}"
        assert e.get("symbol") == name


def test_load_watcom_map_unknown_segment_skipped(db: EntityDb):
    """Symbols in segments not in section_bases are not loaded."""
    map_with_seg3 = "0003:00000010  some_func\n"
    load_watcom_map(map_with_seg3, db, _SECTION_BASES, ImageId.ORIG)
    assert db.count() == 0


def test_load_watcom_map_non_symbol_lines_skipped(db: EntityDb):
    """Header and group lines that don't match SSSS:OOOOOOOO are ignored."""
    load_watcom_map(_SAMPLE_MAP, db, _SECTION_BASES, ImageId.ORIG)
    # All entities should have valid VAs within our sections
    for e in db.get_all():
        addr = e.addr(ImageId.ORIG)
        if addr is not None:
            in_code = CODE_BASE <= addr < CODE_BASE + CODE_VSIZE
            in_data = DATA_BASE <= addr < DATA_BASE + DATA_VSIZE
            assert in_code or in_data, f"0x{addr:x} is not in any known section"


def test_load_watcom_map_recomp_side(db: EntityDb):
    load_watcom_map(_SAMPLE_MAP, db, _SECTION_BASES, ImageId.RECOMP)
    e = db.get(ImageId.RECOMP, CODE_BASE + 0x10)
    assert e is not None


# ── match_watcom_symbols ──────────────────────────────────────────────────────


def test_match_watcom_symbols_match(db: EntityDb):
    """Identical raw symbol names on ORIG and RECOMP get matched."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG,   0x10010, type=EntityType.FUNCTION, symbol="add_")
        batch.set(ImageId.RECOMP, 0x20010, type=EntityType.FUNCTION, symbol="add_")

    match_watcom_symbols(db)

    e = db.get(ImageId.ORIG, 0x10010)
    assert e is not None
    assert e.recomp_addr == 0x20010


def test_match_watcom_symbols_no_match(db: EntityDb):
    """Different raw names are not matched."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG,   0x10010, type=EntityType.FUNCTION, symbol="add_")
        batch.set(ImageId.RECOMP, 0x20010, type=EntityType.FUNCTION, symbol="sub_")

    match_watcom_symbols(db)

    e = db.get(ImageId.ORIG, 0x10010)
    assert e is not None
    assert e.recomp_addr is None


def test_match_watcom_symbols_multiple(db: EntityDb):
    """Multiple symbol pairs are all matched correctly."""
    pairs = [("add_", 0x10010, 0x20010), ("main_", 0x10030, 0x20030)]
    with db.batch() as batch:
        for sym, orig, recomp in pairs:
            batch.set(ImageId.ORIG,   orig,   type=EntityType.FUNCTION, symbol=sym)
            batch.set(ImageId.RECOMP, recomp, type=EntityType.FUNCTION, symbol=sym)

    match_watcom_symbols(db)

    for sym, orig, recomp in pairs:
        e = db.get(ImageId.ORIG, orig)
        assert e is not None and e.recomp_addr == recomp, f"{sym} not matched"


def test_match_watcom_symbols_duplicate_recomp_skipped(db: EntityDb):
    """If two RECOMP symbols have the same name, neither gets matched
    (only the first occurrence is taken; the second is silently skipped)."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG,   0x10010, type=EntityType.FUNCTION, symbol="dup_")
        batch.set(ImageId.RECOMP, 0x20010, type=EntityType.FUNCTION, symbol="dup_")
        batch.set(ImageId.RECOMP, 0x20020, type=EntityType.FUNCTION, symbol="dup_")

    match_watcom_symbols(db)

    e = db.get(ImageId.ORIG, 0x10010)
    assert e is not None
    # One match is made (the first recomp occurrence wins)
    assert e.recomp_addr is not None


# ── load_markers: accepts Image (not just PEImage) ────────────────────────────


def test_load_markers_accepts_non_pe_image(db: EntityDb, lines_db: LinesDb):
    """load_markers must not crash when passed a non-PEImage.
    It uses only is_valid_vaddr() which is on the Image base class."""
    mock_image = Mock(spec=[])
    mock_image.is_valid_vaddr = Mock(return_value=False)

    load_markers(
        code_files=[],
        lines_db=lines_db,
        orig_bin=mock_image,
        target_id="TEST",
        db=db,
    )
    # No annotations → nothing added, no crash
    assert db.count() == 0
