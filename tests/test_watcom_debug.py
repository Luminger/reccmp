"""Tests for the Watcom Debug Info 3.0 parser.

Uses hello_watdbg.exe as the primary fixture — a real binary compiled from
tests/binfiles/le_src/hello.c with Open Watcom v2 (-hw flag, DEBUG WATCOM ALL).

Ground-truth values from inspecting hello_watdbg.exe:

  Module 0: name ends with 'hello.c', lang='c'
  User symbols (mod=0):
    'add_'        code  seg=1 off=0x10   demangled='add'         conv='__watcall'
    'get_answer_' code  seg=1 off=0x1D   demangled='get_answer'  conv='__watcall'
    'main_'       code  seg=1 off=0x2F   demangled='main'        conv='__watcall'
    '_answer'     data  seg=2 off=0x04   demangled='answer'      conv=None
    '_answer_ptr' data  seg=2 off=0x08   demangled='answer_ptr'  conv=None
  Line numbers (module 0, 9 entries, base=0x10):
    line=9  flat=0x0010   line=10 flat=0x001A  line=11 flat=0x001C
    line=13 flat=0x001D   line=14 flat=0x0027  line=15 flat=0x002E
    line=17 flat=0x002F   line=18 flat=0x003A  line=19 flat=0x0049
"""

import struct
from pathlib import Path
from typing import Iterator

import pytest

from reccmp.formats.watcom_debug import (
    WatcomDebugInfo,
    WatcomDebugNotFoundError,
    parse_watcom_debug,
    parse_watcom_debug_file,
)
from .binfiles_test_setup import BINFILE_LE_WATDBG


# ── Fixture ───────────────────────────────────────────────────────────────────


@pytest.fixture(name="watdbg", scope="session")
def fixture_watdbg(bin_loader) -> Iterator[WatcomDebugInfo]:
    path: Path = bin_loader(BINFILE_LE_WATDBG, file_is_required=True)
    yield parse_watcom_debug_file(path)


# ── Invalid / missing signature ───────────────────────────────────────────────


def test_invalid_signature():
    """A blob that does not end with 0x8386 raises WatcomDebugNotFoundError."""
    with pytest.raises(WatcomDebugNotFoundError):
        parse_watcom_debug(b"\x00" * 64)


def test_bad_signature_value():
    """A blob with the right size but a wrong signature raises the error."""
    blob = bytearray(28)
    struct.pack_into("<H", blob, 26, 0x1234)  # wrong signature in last 14 bytes
    with pytest.raises(WatcomDebugNotFoundError):
        parse_watcom_debug(bytes(blob))


def test_file_too_small():
    with pytest.raises(WatcomDebugNotFoundError):
        parse_watcom_debug(b"\x86\x83")  # only 2 bytes


# ── Module parsing ────────────────────────────────────────────────────────────


def test_module_count(watdbg: WatcomDebugInfo):
    """hello_watdbg.exe links 15 modules (hello.c + CRT)."""
    assert len(watdbg.modules) == 15


def test_module_zero_is_source_file(watdbg: WatcomDebugInfo):
    """Module 0 must be our hello.c source file."""
    m = watdbg.modules[0]
    assert m.index == 0
    assert m.name.endswith("hello.c")
    assert m.language == "c"


def test_module_indices_are_sequential(watdbg: WatcomDebugInfo):
    for i, m in enumerate(watdbg.modules):
        assert m.index == i


def test_module_language(watdbg: WatcomDebugInfo):
    """All modules in a C-only binary report language 'c'."""
    for m in watdbg.modules:
        assert m.language == "c"


# ── Symbol parsing ────────────────────────────────────────────────────────────


def _user_syms(watdbg: WatcomDebugInfo):
    return [s for s in watdbg.symbols if s.module_index == 0]


def test_symbol_count_total(watdbg: WatcomDebugInfo):
    """hello_watdbg.exe has 67 global symbols total (user + CRT)."""
    assert len(watdbg.symbols) == 67


def test_user_symbol_count(watdbg: WatcomDebugInfo):
    """Module 0 contributes exactly 5 user-defined symbols."""
    assert len(_user_syms(watdbg)) == 5


def test_code_symbol_add(watdbg: WatcomDebugInfo):
    syms = {s.raw_name: s for s in _user_syms(watdbg)}
    s = syms["add_"]
    assert s.segment == 1
    assert s.offset == 0x10
    assert s.is_code is True
    assert s.is_data is False
    assert s.is_static is False


def test_code_symbol_demangled(watdbg: WatcomDebugInfo):
    """Watcom __watcall code decoration: trailing underscore stripped."""
    syms = {s.raw_name: s for s in _user_syms(watdbg)}
    assert syms["add_"].name == "add"
    assert syms["add_"].calling_convention == "__watcall"
    assert syms["get_answer_"].name == "get_answer"
    assert syms["main_"].name == "main"


def test_data_symbol_answer(watdbg: WatcomDebugInfo):
    syms = {s.raw_name: s for s in _user_syms(watdbg)}
    s = syms["_answer"]
    assert s.segment == 2
    assert s.offset == 0x04
    assert s.is_data is True
    assert s.is_code is False
    assert s.is_static is False


def test_data_symbol_demangled(watdbg: WatcomDebugInfo):
    """Watcom __watcall data decoration: leading underscore stripped."""
    syms = {s.raw_name: s for s in _user_syms(watdbg)}
    assert syms["_answer"].name == "answer"
    assert syms["_answer"].calling_convention is None
    assert syms["_answer_ptr"].name == "answer_ptr"


def test_data_symbol_answer_ptr(watdbg: WatcomDebugInfo):
    syms = {s.raw_name: s for s in _user_syms(watdbg)}
    s = syms["_answer_ptr"]
    assert s.segment == 2
    assert s.offset == 0x08
    assert s.is_data is True


def test_static_symbol(watdbg: WatcomDebugInfo):
    """At least one static symbol must be present in the CRT."""
    statics = [s for s in watdbg.symbols if s.is_static]
    assert len(statics) > 0


def test_undecorated_symbol_unchanged(watdbg: WatcomDebugInfo):
    """Symbols that don't match the Watcom decoration pattern are left as-is."""
    syms = {s.raw_name: s for s in watdbg.symbols}
    # CRT symbols like '__GETDS' have no trailing _ or leading _
    s = syms.get("__GETDS")
    if s is not None:
        assert s.name == "__GETDS"
        assert s.calling_convention is None


# ── Line numbers ──────────────────────────────────────────────────────────────


def test_line_entries_for_module_zero(watdbg: WatcomDebugInfo):
    """Module 0 (hello.c compiled with -d1) should have line entries."""
    mod0_lines = [e for e in watdbg.line_numbers if e.module_index == 0]
    assert len(mod0_lines) == 9


def test_line_numbers_sorted_by_offset(watdbg: WatcomDebugInfo):
    offsets = [e.code_offset for e in watdbg.line_numbers]
    assert offsets == sorted(offsets)


def test_line_flat_offsets(watdbg: WatcomDebugInfo):
    """Verify all 9 flat code offsets for hello.c match known values."""
    mod0 = {e.line: e.code_offset for e in watdbg.line_numbers if e.module_index == 0}
    expected = {
        9:  0x0010,
        10: 0x001A,
        11: 0x001C,
        13: 0x001D,
        14: 0x0027,
        15: 0x002E,
        17: 0x002F,
        18: 0x003A,
        19: 0x0049,
    }
    assert mod0 == expected


def test_line_entry_module_index(watdbg: WatcomDebugInfo):
    """Each line entry's module_index must point to a valid module."""
    for entry in watdbg.line_numbers:
        assert 0 <= entry.module_index < len(watdbg.modules)


def test_crt_modules_have_no_lines(watdbg: WatcomDebugInfo):
    """CRT modules were not compiled with -d1, so they produce no line entries."""
    crt_lines = [e for e in watdbg.line_numbers if e.module_index > 0]
    assert len(crt_lines) == 0
