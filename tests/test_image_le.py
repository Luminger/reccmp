"""Tests for LXImage: LE (Linear Executable) format support.

Uses two real compiled binaries committed to tests/binfiles/:

  hello_plain.exe  — plain DOS/4GW (MZ → LE directly, handled by detect_image)
  hello_pro.exe    — DOS/4GW Professional (MZ → BW chain → inner MZ → LE)

Both contain the same LE payload compiled from tests/binfiles/le_src/hello.c
with Open Watcom v2.  See docs/le-format-support.md for the build recipe.

Ground-truth values used in assertions:

  Code object (obj1): reloc_base=0x10000  virtual_size=0x581
  Data object (obj2): reloc_base=0x20000  virtual_size=0x10090
  imagebase:   0x10000  (minimum of the two bases)
  entry point: 0x1004C  (eip_object=1, eip=0x4C)
  off32 fixup target VAs: 0x90008, 0x90004
"""

import struct
from pathlib import Path
from typing import Iterator

import pytest

from reccmp.formats import LXImage, detect_image
from reccmp.formats.image import ImageSectionFlags
from reccmp.formats.lx import LXHeaderNotFoundError
from reccmp.formats.mz import ImageDosHeader, MZImage
from reccmp.formats.exceptions import InvalidVirtualAddressError

from .binfiles_test_setup import BINFILE_LE_PLAIN, BINFILE_LE_PRO


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(name="le_plain", scope="session")
def fixture_le_plain(bin_loader) -> Iterator[LXImage]:
    """LXImage loaded from hello_plain.exe (plain DOS/4GW, direct MZ→LE)."""
    image = detect_image(bin_loader(BINFILE_LE_PLAIN, file_is_required=True))
    assert isinstance(image, LXImage)
    yield image


@pytest.fixture(name="le_pro_path", scope="session")
def fixture_le_pro_path(bin_loader) -> Iterator[Path]:
    """Path to hello_pro.exe (DOS/4GW Pro, MZ→BW chain→inner MZ→LE).

    detect_image() returns MZImage for this file because the outer MZ e_lfanew
    points at a BW stub, not LE.  Tests that need an LXImage must walk the BW
    chain themselves — see test_pro_bw_walk_reaches_le for the canonical pattern.
    """
    yield bin_loader(BINFILE_LE_PRO, file_is_required=True)


# ── detect_image behaviour ────────────────────────────────────────────────────


def test_detect_image_plain_returns_lximage(bin_loader):
    """detect_image() returns LXImage for a plain DOS/4GW executable."""
    path = bin_loader(BINFILE_LE_PLAIN, file_is_required=True)
    image = detect_image(path)
    assert isinstance(image, LXImage)


def test_detect_image_pro_returns_mzimage(le_pro_path: Path):
    """detect_image() returns MZImage (not LXImage, not an error) for a
    DOS/4GW Pro executable, because the outer MZ e_lfanew points at BW."""
    image = detect_image(le_pro_path)
    assert isinstance(image, MZImage)
    assert not isinstance(image, LXImage)


# ── DOS/4GW Pro: BW chain walk ────────────────────────────────────────────────


def test_pro_bw_walk_reaches_le(le_pro_path: Path):
    """Walking the BW chain manually then calling LXImage.from_memory() with the
    inner MZ header and its file offset produces a valid, fully functional LXImage.

    This is the canonical pattern for loading DOS/4GW Pro executables.
    The BW 'next_header_pos' field is at offset +28 within each BW header.
    """
    data = le_pro_path.read_bytes()
    outer_mz, _ = ImageDosHeader.from_memory(data, 0)

    # Outer MZ e_lfanew must point at a BW stub, not LE.
    assert data[outer_mz.e_lfanew : outer_mz.e_lfanew + 2] == b"BW"

    # Walk the BW chain until we reach a non-BW header (the inner MZ).
    inner_mz_offset = outer_mz.e_lfanew
    while data[inner_mz_offset : inner_mz_offset + 2] == b"BW":
        inner_mz_offset = struct.unpack_from("<I", data, inner_mz_offset + 28)[0]

    assert data[inner_mz_offset : inner_mz_offset + 2] == b"MZ"
    inner_mz, _ = ImageDosHeader.from_memory(data, inner_mz_offset)
    image = LXImage.from_memory(data, inner_mz, le_pro_path, mz_offset=inner_mz_offset)

    assert isinstance(image, LXImage)
    assert len(image.sections) == 2
    assert image.entry == 0x1004C


def test_pro_and_plain_have_identical_entry(le_plain: LXImage, le_pro_path: Path):
    """Both binaries carry the same LE payload; their entry points must match."""
    data = le_pro_path.read_bytes()
    offset = struct.unpack_from("<I", data, 0x3C)[0]  # outer e_lfanew → BW
    while data[offset : offset + 2] == b"BW":
        offset = struct.unpack_from("<I", data, offset + 28)[0]
    inner_mz, _ = ImageDosHeader.from_memory(data, offset)
    pro_image = LXImage.from_memory(data, inner_mz, le_pro_path, mz_offset=offset)

    assert le_plain.entry == pro_image.entry


# ── Object table parsing ──────────────────────────────────────────────────────


def test_le_section_count(le_plain: LXImage):
    assert len(le_plain.sections) == 2


def test_le_code_object(le_plain: LXImage):
    code = le_plain.sections[0]
    assert code.virtual_address == 0x10000
    assert code.virtual_size == 0x581
    assert ImageSectionFlags.EXECUTE in code.flags
    assert ImageSectionFlags.READ in code.flags


def test_le_data_object(le_plain: LXImage):
    data = le_plain.sections[1]
    assert data.virtual_address == 0x20000
    assert data.virtual_size == 0x10090
    assert ImageSectionFlags.WRITE in data.flags
    assert ImageSectionFlags.READ in data.flags
    assert ImageSectionFlags.EXECUTE not in data.flags


# ── seek() ────────────────────────────────────────────────────────────────────


def test_le_seek_code_base(le_plain: LXImage):
    view, remaining = le_plain.seek(0x10000)
    assert remaining == 0x581
    assert len(view) > 0


def test_le_seek_code_mid(le_plain: LXImage):
    _, remaining = le_plain.seek(0x10010)
    assert remaining == 0x581 - 0x10


def test_le_seek_data_base(le_plain: LXImage):
    _, remaining = le_plain.seek(0x20000)
    assert remaining == 0x10090


def test_le_seek_invalid_zero(le_plain: LXImage):
    with pytest.raises(InvalidVirtualAddressError):
        le_plain.seek(0x0)


def test_le_seek_invalid_between_objects(le_plain: LXImage):
    """Gap between code end (0x10581) and data start (0x20000) is unmapped."""
    with pytest.raises(InvalidVirtualAddressError):
        le_plain.seek(0x10581)


def test_le_seek_beyond_data(le_plain: LXImage):
    """Address past the end of the data object is invalid."""
    with pytest.raises(InvalidVirtualAddressError):
        le_plain.seek(0x20000 + 0x10090)


def test_le_read_returns_bytes(le_plain: LXImage):
    """Image.read() must return exactly the requested number of bytes."""
    result = le_plain.read(0x10000, 4)
    assert isinstance(result, bytes)
    assert len(result) == 4


# ── imagebase, entry ──────────────────────────────────────────────────────────


def test_le_imagebase(le_plain: LXImage):
    assert le_plain.imagebase == 0x10000


def test_le_entry(le_plain: LXImage):
    assert le_plain.entry == 0x1004C


# ── relocations / is_relocated_addr ──────────────────────────────────────────


def test_le_is_relocated_addr_target_true(le_plain: LXImage):
    """0x20008 is answer_ptr's VA in the data segment; code holds a fixup pointing there."""
    assert le_plain.is_relocated_addr(0x20008) is True


def test_le_is_relocated_addr_target_true_second(le_plain: LXImage):
    """0x20004 is answer's VA; answer_ptr holds a fixup pointing there."""
    assert le_plain.is_relocated_addr(0x20004) is True


def test_le_is_relocated_addr_code_base_false(le_plain: LXImage):
    """The code base address itself is not a fixup target."""
    assert le_plain.is_relocated_addr(0x10000) is False


def test_le_is_relocated_addr_zero_false(le_plain: LXImage):
    assert le_plain.is_relocated_addr(0x0) is False


def test_le_relocations_are_source_vas(le_plain: LXImage):
    """relocations is the set of virtual addresses WHERE fixups are applied.
    hello.c links in the full Watcom CRT so there are many fixup source locations."""
    assert len(le_plain.relocations) >= 2
    # All source VAs must fall within a valid object's virtual range
    for va in le_plain.relocations:
        assert le_plain.is_valid_vaddr(va), f"Source VA 0x{va:x} is not in any object"


# ── region iterators ──────────────────────────────────────────────────────────


def test_le_get_code_regions_one(le_plain: LXImage):
    regions = list(le_plain.get_code_regions())
    assert len(regions) == 1
    assert regions[0].addr == 0x10000
    # size is virtual_size; data is capped to that — no physical-page zero-padding
    assert regions[0].size == 0x581
    assert len(regions[0].data) == 0x581


def test_le_get_data_regions_one(le_plain: LXImage):
    regions = list(le_plain.get_data_regions())
    assert len(regions) == 1
    assert regions[0].addr == 0x20000


def test_le_get_const_regions_empty(le_plain: LXImage):
    """Caesar II / hello.c have no read-only data section."""
    assert list(le_plain.get_const_regions()) == []


# ── get_relative_addr ─────────────────────────────────────────────────────────


def test_le_relative_addr_code_base(le_plain: LXImage):
    assert le_plain.get_relative_addr(0x10000) == (0, 0)


def test_le_relative_addr_code_offset(le_plain: LXImage):
    assert le_plain.get_relative_addr(0x1004C) == (0, 0x4C)


def test_le_relative_addr_data_base(le_plain: LXImage):
    assert le_plain.get_relative_addr(0x20000) == (1, 0)


def test_le_relative_addr_invalid(le_plain: LXImage):
    with pytest.raises(InvalidVirtualAddressError):
        le_plain.get_relative_addr(0x0)


# ── imports ───────────────────────────────────────────────────────────────────


def test_le_imports_empty(le_plain: LXImage):
    assert list(le_plain.imports) == []


# ── is_valid_vaddr ────────────────────────────────────────────────────────────


def test_le_is_valid_vaddr_code(le_plain: LXImage):
    assert le_plain.is_valid_vaddr(0x10000) is True
    assert le_plain.is_valid_vaddr(0x1004C) is True


def test_le_is_valid_vaddr_data(le_plain: LXImage):
    assert le_plain.is_valid_vaddr(0x20000) is True


def test_le_is_valid_vaddr_invalid(le_plain: LXImage):
    assert le_plain.is_valid_vaddr(0x0) is False
    assert le_plain.is_valid_vaddr(0x10581) is False


# ── LXHeaderNotFoundError ─────────────────────────────────────────────────────


def test_lx_header_not_found():
    with pytest.raises(LXHeaderNotFoundError):
        LXImageHeader_cls = LXImage.__dataclass_fields__  # noqa: just trigger import
        from reccmp.formats.lx import LXImageHeader
        LXImageHeader.from_memory(b"PE\x00\x00", 0)
