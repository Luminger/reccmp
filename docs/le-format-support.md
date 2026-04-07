# LE (Linear Executable) Format Support Plan

This document describes the work required to make reccmp a first-class tool for
decompilation projects targeting **DOS/4GW 32-bit LE (Linear Executable)** binaries
compiled with **Open Watcom C/C++**. The immediate motivation is
[Caesar II](https://github.com/isledecomp/caesar2), but the changes are designed to
benefit any future project of this type.

Each tier is designed to be committed and verified independently. The testing strategy
for each tier is described alongside the implementation.

---

## Background

### The LE executable format

LE (Linear Executable) is the 32-bit flat-model format used by OS/2 2.x and DOS/4GW.
It replaced the 16-bit NE format. Unlike PE, there is no single imagebase; instead, each
"object" (equivalent to a PE section) carries its own `reloc_base_addr`. The format is
sometimes labelled LX (Linear eXecutable) in documentation and tooling — LX is a minor
revision used by later OS/2 versions, but the two share an identical magic (`LE`) and a
nearly identical header layout. reccmp's existing `LXImage` skeleton already uses the
`LE` magic and the correct struct layout.

### DOS/4GW variants and the file layout question

The outer file layout of a DOS/4GW executable depends on **which variant of DOS/4GW
was licensed** by the game developer. This affects how `detect_image()` finds the LE
header:

#### Plain DOS/4GW (freeware)

The most common case. Used by the vast majority of Watcom-compiled DOS games.

```
[MZ header]   e_lfanew ──────────────────────┐
[DOS stub code]                               │
[LE header]  ◄────────────────────────────────┘
[LE data pages]
```

`detect_image()` already handles this: it reads `data[mz_header.e_lfanew : +2]` and
finds `LE`, returning an `LXImage`. **No changes to `detect_image()` are needed for
this case.**

#### DOS/4GW Professional (commercial, Rational Systems / Tenberry)

Used by a small number of titles that licensed the Pro variant — primarily
Sierra/Impressions games including Caesar II. The `BW` stub (magic bytes `42 57`) is
DOS/4GW Pro's own protected-mode loader, and it wraps the LE in an extra layer:

```
[Outer MZ header]   e_lfanew ──┐
[DOS stub code]                │
[BW stub #1]   ◄───────────────┘   (DOS/4GW Pro VMM loader: VMM.EXP)
  next_header_pos ─────────────┐
[BW stub #2]   ◄───────────────┘   (DOS/4GW Pro kernel: 4GWPRO.EXP)
  next_header_pos ─────────────┐
[Inner MZ header]  ◄───────────┘   e_lfanew ──┐
[Inner DOS stub]                               │
[LE header]   ◄────────────────────────────────┘
[LE data pages]
```

The outer MZ's `e_lfanew` points into the BW stub region, **not** at `LE`. So
`detect_image()` reads `BW` at that offset and currently falls through to returning a
plain `MZImage`. The LE header is only reachable by walking the BW chain to its end,
then following the final `next_header_pos` to the inner MZ, whose `e_lfanew` then points
at LE.

**Decision: keep BW-chain walking out of reccmp.** DOS/4GW Pro is a narrow subset of
an already-niche format. Embedding BW-chain traversal into `detect_image()` would add
complexity to the core detection path for a case that affects only a handful of titles.
Instead, the calling project is responsible for resolving the inner MZ offset and calling
`LXImage.from_memory()` directly with that header. The existing `LXImage.from_memory()`
signature already accepts an `ImageDosHeader` — if the caller parses the inner MZ with
`ImageDosHeader.from_memory(data, inner_mz_offset)` and passes the result in, no new
factory method is required.

For projects that need it, a small helper function can live in the project's own codebase:

```python
def load_le_image(filepath: Path) -> LXImage:
    """Load an LE image, handling both plain DOS/4GW and DOS/4GW Pro layouts."""
    data = filepath.read_bytes()
    mz, _ = ImageDosHeader.from_memory(data, 0)

    sig = data[mz.e_lfanew : mz.e_lfanew + 2]
    if sig == b"LE":
        # Plain DOS/4GW: MZ → LE directly
        return LXImage.from_memory(data, mz, filepath)
    elif sig == b"BW":
        # DOS/4GW Pro: walk BW chain to find the inner MZ → LE
        inner_mz_offset = _walk_bw_chain(data, mz.e_lfanew)
        inner_mz, _ = ImageDosHeader.from_memory(data, inner_mz_offset)
        return LXImage.from_memory(data, inner_mz, filepath)
    else:
        raise ValueError(f"Unexpected signature at e_lfanew: {sig!r}")
```

---

## Test infrastructure prerequisite: real compiled binaries

Instead of a synthetic binary builder, LE format tests use two real binaries compiled
from the same minimal C source with Open Watcom v2. These are committed to the repository
at `tests/binfiles/` alongside the existing `LEGO1.DLL` and `SKI.EXE` fixtures, and
registered in `tests/binfiles_test_setup.py`.

Using real binaries rather than hand-assembled byte strings is preferable for LE because:
- The fixup record table format is complex enough that synthetic construction would
  duplicate and likely diverge from the real parser under test.
- Real wlink output exercises the exact byte layout the `LXImage` parser must handle.
- Both format variants (plain DOS/4GW and DOS/4GW Pro) are covered with a single source.

### Source file: `tests/binfiles/le_src/hello.c`

```c
/* Minimal DOS/4GW program for reccmp LE format testing.
   Two exported functions so we can test symbol matching,
   one data symbol so we can test data section handling,
   and a fixup (pointer to data) so we can test is_relocated_addr(). */

int answer = 42;
int *answer_ptr = &answer;   /* fixup: pointer into data segment */

int add(int a, int b) {
    return a + b;
}

int get_answer(void) {
    return *answer_ptr;
}

int main(void) {
    return add(get_answer(), 1);
}
```

### Build recipe

Requires Open Watcom v2 (`wcc386`, `wlink`) and Python 3. On the caesar2 devenv these
are available directly in PATH.

#### Step 1 — Compile

```bash
wcc386 -bt=dos4g -mf -3r -fpi87 -d1 -fo=hello.obj hello.c
```

Flag meanings:

| Flag | Effect |
|------|--------|
| `-bt=dos4g` | Target DOS/4GW |
| `-mf` | Flat memory model (required for 32-bit LE) |
| `-3r` | Register-based calling convention (Watcom default) |
| `-fpi87` | Inline x87 FP instructions, no emulation |
| `-d1` | Line-number debug info only (matches Caesar II's debug level) |

#### Step 2 — Link: plain DOS/4GW (`hello_plain.exe`)

wlink embeds its own minimal MZ stub by default. The output is a clean MZ → LE layout
that `detect_image()` handles without any special casing.

```bash
WATCOM=/path/to/open-watcom-v2

wlink \
  FORMAT os2 le \
  OPTION osname='DOS/4G' \
  OPTION NODEFAULTLIBS \
  OPTION START=_cstart_ \
  OPTION QUIET \
  LIBPATH "$WATCOM/lib386" \
  LIBPATH "$WATCOM/lib386/dos" \
  LIB clib3r \
  LIB math387r \
  FILE hello.obj \
  NAME hello_plain.exe
```

Result: `hello_plain.exe` — 5 090 bytes. The outer MZ `e_lfanew = 0x70` points directly
at the LE header. Two objects: code at `reloc_base=0x10000`, data at `reloc_base=0x20000`.
Two off32 internal fixup records (for `answer_ptr` and the pointer value it holds).

#### Step 3 — Extract the DOS/4GW Pro stubs

The BW chain components are extracted from a DOS/4GW Pro binary (such as Caesar II's
`PS.EXE`). They are committed to `tests/binfiles/le_stubs/` and must not be
regenerated unless a newer Pro version is specifically needed.

```python
import struct

data = open("PS.EXE", "rb").read()

# Locate the BW chain start (immediately after the outer MZ load module)
last_page = struct.unpack_from("<H", data, 2)[0]
pages     = struct.unpack_from("<H", data, 4)[0]
bw1_start = pages * 512 - 512 + last_page   # = 0xF474 for Caesar II PS.EXE

# BW1: VMM.EXP
bw1_last  = struct.unpack_from("<H", data, bw1_start + 2)[0]
bw1_pages = struct.unpack_from("<H", data, bw1_start + 4)[0]
bw1_size  = bw1_pages * 512 - 512 + bw1_last   # = 0xEA50 = 59 984 bytes
open("tests/binfiles/le_stubs/vmm.exp", "wb").write(data[bw1_start : bw1_start + bw1_size])

# BW2: 4GWPRO.EXP  (next_header_pos field of BW1 is at offset +28)
bw2_start = struct.unpack_from("<I", data, bw1_start + 28)[0]  # = 0x1E0C4
bw2_last  = struct.unpack_from("<H", data, bw2_start + 2)[0]
bw2_pages = struct.unpack_from("<H", data, bw2_start + 4)[0]
bw2_size  = bw2_pages * 512 - 512 + bw2_last   # = 0x16FE0 = 94 176 bytes
open("tests/binfiles/le_stubs/4gwpro.exp", "wb").write(data[bw2_start : bw2_start + bw2_size])

# Inner MZ stub: from the address that BW2's next_header_pos points to,
# for exactly e_lfanew bytes (the MZ stub portion, before the LE header).
inner_mz_start = struct.unpack_from("<I", data, bw2_start + 28)[0]  # = 0x352A4
inner_lfanew   = struct.unpack_from("<I", data, inner_mz_start + 0x3C)[0]  # = 0x2AA8
open("tests/binfiles/le_stubs/dos4gpro.stub", "wb").write(
    data[inner_mz_start : inner_mz_start + inner_lfanew]
)
```

#### Step 4 — Link: DOS/4GW Pro (`hello_pro.exe`)

wlink's `STUB=` option replaces the embedded MZ stub with a supplied file. We supply
the inner MZ stub extracted above so that wlink's output is already an inner MZ → LE
layout. Then a short Python script prepends the BW chain to produce the full Pro layout.

```bash
# 4a. Link with the inner MZ stub
wlink \
  FORMAT os2 le \
  OPTION osname='DOS/4G' \
  OPTION NODEFAULTLIBS \
  OPTION START=_cstart_ \
  OPTION STUB="tests/binfiles/le_stubs/dos4gpro.stub" \
  OPTION QUIET \
  LIBPATH "$WATCOM/lib386" \
  LIBPATH "$WATCOM/lib386/dos" \
  LIB clib3r \
  LIB math387r \
  FILE hello.obj \
  NAME hello_pro_nostub.exe
```

```python
# 4b. Prepend the BW chain
import struct

bw1 = open("tests/binfiles/le_stubs/vmm.exp",       "rb").read()
bw2 = open("tests/binfiles/le_stubs/4gwpro.exp",    "rb").read()
inner = open("hello_pro_nostub.exe", "rb").read()

# Compute absolute positions in the assembled file
OUTER_MZ_SIZE = 512   # one 512-byte page for the outer MZ stub
bw1_start  = OUTER_MZ_SIZE
bw2_start  = bw1_start + len(bw1)
inner_start = bw2_start + len(bw2)

# Patch BW chain next_header_pos fields to reflect new positions
bw1_patched = bytearray(bw1)
bw2_patched = bytearray(bw2)
struct.pack_into("<I", bw1_patched, 28, bw2_start)
struct.pack_into("<I", bw2_patched, 28, inner_start)

# Build a minimal outer MZ header (512 bytes)
# e_lfanew → bw1_start = 512, so detect_image() sees b'BW' there
outer_mz = bytearray(OUTER_MZ_SIZE)
struct.pack_into("<H", outer_mz, 0x00, 0x5A4D)   # 'MZ'
struct.pack_into("<H", outer_mz, 0x02, 0)         # e_cblp (full last page)
struct.pack_into("<H", outer_mz, 0x04, 1)         # e_cp
struct.pack_into("<H", outer_mz, 0x08, 4)         # e_cparhdr (64 bytes)
struct.pack_into("<H", outer_mz, 0x0C, 0xFFFF)    # e_maxalloc
struct.pack_into("<I", outer_mz, 0x3C, bw1_start) # e_lfanew → BW1
msg = b"This program requires DOS/4GW Professional.\r\n$"
outer_mz[0x40 : 0x40 + len(msg)] = msg

result = bytes(outer_mz) + bytes(bw1_patched) + bytes(bw2_patched) + inner
open("tests/binfiles/hello_pro.exe", "wb").write(result)
```

Result: `hello_pro.exe` — 170 582 bytes. Structure:
```
0x000000  outer MZ (512 bytes)     e_lfanew=0x200 → BW
0x000200  BW1 / VMM.EXP            next_header_pos=0xEC50
0x00EC50  BW2 / 4GWPRO.EXP         next_header_pos=0x25C30
0x025C30  inner MZ stub            e_lfanew=0x2AB0 → LE
0x0286E0  LE header                two objects, same layout as plain
```

Both binaries contain identical LE payloads — the same two objects, the same two fixup
records, the same entry point — and differ only in the outer wrapper. This makes them
ideal for testing that `LXImage.from_memory()` produces consistent results regardless
of which path was used to locate the inner MZ header.

### Known values for test assertions

These are the ground-truth values derived from the compiled binaries:

| Property | Value |
|----------|-------|
| Code object (`obj1`) `reloc_base_addr` | `0x10000` |
| Code object virtual size | `0x581` (1409 bytes) |
| Data object (`obj2`) `reloc_base_addr` | `0x20000` |
| Data object virtual size | `0x10090` |
| `imagebase` (min of the two) | `0x10000` |
| Entry point (`eip_object=1`, `eip=0x4C`) | `0x1004C` |
| `is_relocated_addr(0x90008)` | `True` (target of off32 fixup) |
| `is_relocated_addr(0x90004)` | `True` (target of off32 fixup) |
| `is_relocated_addr(0x10000)` | `False` |
| `detect_image(hello_plain.exe)` | `LXImage` |
| `detect_image(hello_pro.exe)` | `MZImage` (BW at `e_lfanew`) |

---

## Implementation plan

Work is divided into eight tiers. Tiers 1–3 are strict prerequisites for all later work.
Tiers 4–6 can proceed largely in parallel once Tier 3 is complete. Tiers 7–8 are
integration and project-config work that lands last.

---

### Tier 1 — `reccmp/formats/lx.py`: Complete `LXImage`

The class exists as a stub. Every method raises `NotImplementedError`. All eight items
below must be implemented before any comparison logic can use an LE binary.

#### 1.1 Parse the object table in `from_memory()`

Read `header.nb_objects_in_module` entries from the object table at
`le_offset + header.object_table_off`. Each entry is 24 bytes:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | `virtual_size` |
| 4 | 4 | `reloc_base_addr` |
| 8 | 4 | `flags` (RWX bits, 32-bit flag, etc.) |
| 12 | 4 | `page_table_index` (1-based) |
| 16 | 4 | `num_pages` |
| 20 | 4 | reserved |

Compute the physical file range for each object:

```
file_offset = mz_header_offset + header.data_pages_offset
            + (page_table_index - 1) * header.page_size
file_size   = (num_pages - 1) * header.page_size + last_page_size
```

where `last_page_size` is `header.page_offset_shift` — this field is named for the LX
variant; in LE files it stores the size of the final page, not a shift count.

Build a `tuple[ImageSection, ...]` from these entries, populating `virtual_range`,
`physical_range`, `view`, `name` (e.g. `"obj1"`, `"obj2"`), and `flags`
(`ImageSectionFlags.EXECUTE` for code objects, `ImageSectionFlags.WRITE` for data,
`ImageSectionFlags.READ` for all).

#### 1.2 Implement `seek(vaddr)`

```python
def seek(self, vaddr: int) -> tuple[bytes, int]:
    for section in self.sections:
        if section.contains_vaddr(vaddr):
            offset = vaddr - section.virtual_address
            view = section.view[offset:]
            return bytes(view), section.virtual_size - offset
    raise InvalidVirtualAddressError(f"0x{vaddr:x} not in any LE object")
```

This is the single method that `Image.read()`, `FunctionComparator`, and all other
reccmp machinery ultimately calls. Everything else in this tier unlocks once this exists.

#### 1.3 Implement `imagebase` property

Return the lowest `reloc_base_addr` across all objects. For Caesar II this is `0x10000`
(the code segment). reccmp uses `imagebase` as a lower-bound threshold when deciding
whether an immediate operand could be a pointer; it does not need to be exact.

#### 1.4 Implement `relocations` property and `is_relocated_addr()`

Parse the LE fixup tables to build the set of virtual addresses that are *targets* of
internal off32 relocations — i.e., the addresses that get patched at load time:

1. Read fixup page table at `le_offset + header.fixup_page_table_offset`:
   `(num_pages + 1)` × 4-byte entries giving byte offsets into the fixup record table
   for each page.
2. Walk the fixup record table at `le_offset + header.fixup_record_table_offset`.
   For each record with source type `OSF_SOURCE_OFF_32` and target type
   `OSF_TARGET_INTERNAL`, compute the target virtual address as
   `objects[target_obj - 1].reloc_base_addr + target_offset` and add it to the set.

`is_relocated_addr(addr)` returns `addr in self._relocated_addrs`.

`ParseAsm` calls `is_relocated_addr()` to decide whether a large immediate value in a
disassembled instruction is a pointer that should be replaced with a named placeholder
rather than left as a literal number.

#### 1.5 Implement `get_relative_addr(addr)`

Return `(object_index_0based, offset_within_object)` for a given virtual address.
Used by reccmp internal passes that work in section-relative terms.

#### 1.6 Implement `get_code_regions()`, `get_data_regions()`, `get_const_regions()`

Yield `ImageRegion(addr=section.virtual_address, data=bytes(section.view), size=section.virtual_size)`
for executable, writable, and read-only sections respectively.

Caesar II has exactly two objects: code (execute+read) and data (write+read). There are
no read-only const sections, so `get_const_regions()` yields nothing. As a result, the
float-constant analysis pass will find no floating-point constants, which is correct —
Watcom stores float data in the writable data segment, not a separate `.rdata` section.

#### 1.7 Implement `entry` property

Return `objects[header.eip_object_nb - 1].reloc_base_addr + header.eip`.

This is added as a plain (non-abstract) property on the `LXImage` class. The
corresponding change to the base `Image` class is in Tier 3. These can be committed
independently: add `entry` to `LXImage` in Tier 1, add the base-class declaration in
Tier 3.

#### 1.8 Implement `imports` as an empty iterator

LE does not use a Windows-style IAT. External references are encoded in the fixup record
table with target type `OSF_TARGET_EXT_ORD` or `OSF_TARGET_EXT_NAME`. These are not
currently needed for comparison purposes and are out of scope. Return `iter([])`.

#### Tier 1 tests — `tests/test_image_le.py`

Tests use the `hello_plain.exe` and `hello_pro.exe` fixtures registered in
`binfiles_test_setup.py`. Both are committed to the repository so they are always
present in CI. Add two session-scoped fixtures to `conftest.py`:

```python
@pytest.fixture(name="le_plain", scope="session")
def fixture_le_plain(bin_loader) -> Iterator[LXImage]:
    image = detect_image(bin_loader(BINFILE_LE_PLAIN, file_is_required=True))
    assert isinstance(image, LXImage)
    yield image

@pytest.fixture(name="le_pro_path", scope="session")
def fixture_le_pro_path(bin_loader) -> Iterator[Path]:
    # hello_pro.exe has BW at e_lfanew so detect_image returns MZImage.
    # Tests that need an LXImage must walk the BW chain themselves.
    yield bin_loader(BINFILE_LE_PRO, file_is_required=True)
```

Tests to add, using the ground-truth values from the known-values table above:

| Test | Fixture | What it verifies |
|------|---------|-----------------|
| `test_le_from_memory_sections` | `le_plain` | `len(image.sections) == 2` |
| `test_le_seek_code_base` | `le_plain` | `seek(0x10000)` succeeds; remaining == `0x581` |
| `test_le_seek_data_base` | `le_plain` | `seek(0x20000)` succeeds |
| `test_le_seek_mid_object` | `le_plain` | `seek(0x10010)` remaining == `0x581 - 0x10` |
| `test_le_seek_invalid` | `le_plain` | `seek(0x0)` raises `InvalidVirtualAddressError` |
| `test_le_imagebase` | `le_plain` | `image.imagebase == 0x10000` |
| `test_le_entry` | `le_plain` | `image.entry == 0x1004C` |
| `test_le_get_code_regions` | `le_plain` | Yields exactly one region at `addr=0x10000` |
| `test_le_get_data_regions` | `le_plain` | Yields exactly one region at `addr=0x20000` |
| `test_le_get_const_regions` | `le_plain` | Yields nothing |
| `test_le_is_relocated_addr_true` | `le_plain` | `is_relocated_addr(0x90008)` is `True` |
| `test_le_is_relocated_addr_true_2` | `le_plain` | `is_relocated_addr(0x90004)` is `True` |
| `test_le_is_relocated_addr_false` | `le_plain` | `is_relocated_addr(0x10000)` is `False` |
| `test_detect_image_plain` | path | `detect_image(hello_plain.exe)` returns `LXImage` |
| `test_detect_image_pro_returns_mzimage` | path | `detect_image(hello_pro.exe)` returns `MZImage`, does not raise |
| `test_pro_bw_walk_reaches_le` | `le_pro_path` | Walking the BW chain then calling `LXImage.from_memory()` produces a valid image with `entry == 0x1004C` |

The last test is the canonical demonstration of the DOS/4GW Pro loading pattern:

```python
def test_pro_bw_walk_reaches_le(le_pro_path: Path):
    data = le_pro_path.read_bytes()
    outer_mz, _ = ImageDosHeader.from_memory(data, 0)
    assert data[outer_mz.e_lfanew : outer_mz.e_lfanew + 2] == b"BW"

    # Walk BW chain: next_header_pos is at offset +28 within each BW header
    offset = outer_mz.e_lfanew
    while data[offset : offset + 2] == b"BW":
        offset = struct.unpack_from("<I", data, offset + 28)[0]

    assert data[offset : offset + 2] == b"MZ"
    inner_mz, _ = ImageDosHeader.from_memory(data, offset)
    image = LXImage.from_memory(data, inner_mz, le_pro_path)

    assert isinstance(image, LXImage)
    assert image.entry == 0x1004C
    assert len(image.sections) == 2
```

Regression: all existing `test_image_pe.py` and `test_image_ne.py` tests must continue
to pass unchanged.

---

### Tier 2 — `reccmp/formats/detect.py`: Document the plain DOS/4GW path

No code changes are required in `detect_image()` for plain DOS/4GW. Once `LXImage` is
complete (Tier 1), `detect_image()` will already return a fully functional `LXImage` for
any file whose outer MZ's `e_lfanew` points directly at `LE`.

The only addition is a **comment** in `detect_image()` noting that:
- `b"LE"` → plain DOS/4GW, handled.
- `b"BW"` → DOS/4GW Pro; the caller must resolve the inner MZ and call
  `LXImage.from_memory()` directly with it. The function returns a plain `MZImage` in
  this case because it cannot safely walk the BW chain without knowing the format.

#### Tier 2 tests

Covered by `test_detect_image_plain_dos4gw` and `test_detect_image_bw_returns_mzimage`
in Tier 1. No separate test file is needed.

---

### Tier 3 — `reccmp/formats/image.py`: Promote PE-specific properties to the base class

Two properties used throughout reccmp are currently PE-only. Promoting them to the base
class unblocks Tiers 4–6. Both must use **non-abstract defaults** rather than
`@abstractmethod` declarations — the existing `RawImage` test helper has
`# pylint: disable=abstract-method` and deliberately leaves abstract methods
unimplemented. Making new properties abstract would break the large body of tests that
use `RawImage` as a drop-in image mock.

#### 3.1 `relocations` property on `Image`

Add as a regular property returning `frozenset()` by default. `PEImage` keeps its
existing implementation (overrides the base). `LXImage` overrides with the
fixup-derived set from Tier 1.4.

#### 3.2 `entry` property on `Image`

Add as a regular property with a `raise NotImplementedError` body (not `@abstractmethod`).
`PEImage` already has `entry` as a cached property; it satisfies this interface without
any changes. `LXImage` implements it per Tier 1.7.

#### Tier 3 tests

Regression: existing `test_image_pe.py::test_basic` asserts `binfile.entry == 0x1008C860`.
This must continue to pass. No new test file is strictly needed, but add
`test_image_le.py::test_le_entry` and `test_image_le.py::test_le_relocations_base_class`
to confirm the interface is respected.

Specifically confirm that `RawImage`-based tests in `test_compare_analyze.py` and
`test_compare_init.py` still pass — these use `Mock(spec=[])` and `RawImage` without
implementing `relocations` or `entry`, and should be unaffected by the default
implementations.

---

### Tier 4 — Analysis functions: generalize type hints and add guards

All changes are in `reccmp/analysis/` and `reccmp/compare/analyze.py`.

#### 4.1 `analysis/float_const.py` — `find_float_consts(image: Image)`

Change the type hint from `PEImage` to `Image`. The function uses
`image.get_code_regions()`, `image.get_const_regions()`, `image.relocations`, and
`image.read()` — all of which are now on the base class or implemented on `LXImage`.
For Caesar II, `get_const_regions()` returns nothing, so no floats are found. This is
correct behaviour.

#### 4.2 `analysis/funcinfo.py` — `find_funcinfo`, `find_eh_handlers` → accept `Image`

Change type hints from `PEImage` to `Image`. These functions scan for the MSVC SEH
magic bytes `\x20\x05\x93\x19`. Watcom does not emit these structures, so both functions
return empty iterators on any LE image without any conditional logic.

#### 4.3 `analysis/imports.py` — `find_import_thunks` → accept `Image`

Change the type hint from `PEImage` to `Image` for consistency. The guard
`if not isinstance(binfile, PEImage): return` in `analyze.create_import_thunks` already
prevents this from running on LE images and should be retained.

#### 4.4 `compare/analyze.py` — add guards for PE/MSVC-only passes

The following functions in `analyze.py` use PE-specific features. Add
`if not isinstance(binfile, PEImage): return` guards and update type hints to `Image`
where appropriate:

| Function | PE-specific dependency | Action |
|----------|----------------------|--------|
| `match_entry` | `orig_bin.entry` | Change to `Image`; property now on base (Tier 3.2) |
| `create_analysis_strings` | `binfile.relocations`, `binfile.iter_string()` | Add guard; `iter_string` is PE-only |
| `create_thunks` | `binfile.thunks` (incremental build thunks) | Add guard |
| `match_exports` | `binfile.exports` (PE export table) | Add guard |
| `create_analysis_vtordisps` | MSVC vtordisp patterns | Add guard |
| `create_seh_entities` | MSVC SEH (`find_eh_handlers`) | Add guard (belt-and-suspenders; returns empty anyway) |

`create_analysis_floats`, `complete_partial_floats`, `complete_partial_strings`,
`create_imports` are already generic or will work once `seek()` is implemented.

#### Tier 4 tests

The existing `test_compare_analyze.py` tests use `Mock(spec=[])` for the binary, not
`PEImage` directly. They pass before and after this tier because the mocks already
don't expose PE-specific attributes — the guards just make the intent explicit.

Add new tests to `test_compare_analyze.py` passing an `LXImage` (from the `LEImageBuilder`
fixture) where the guarded functions are called. Each must return without error and
without adding anything to the database:

| Test | Function under test | Expected |
|------|--------------------|---------| 
| `test_create_analysis_strings_le` | `create_analysis_strings` | No entities added (guard fires) |
| `test_create_thunks_le` | `create_thunks` | No entities added (guard fires) |
| `test_match_exports_le` | `match_exports` | No matches added (guard fires) |
| `test_create_seh_le` | `create_seh_entities` | No entities added (guard fires) |
| `test_find_float_consts_le` | `find_float_consts` | Empty iterator (no const regions) |
| `test_find_eh_handlers_le` | `find_eh_handlers` | Empty iterator (no MSVC SEH magic) |

---

### Tier 5 — `reccmp/formats/watcom_debug.py`: Watcom Debug Info 3.0 parser

Create a new module `reccmp/formats/watcom_debug.py`. This is a parser for the debug
section appended to the end of LE executables built with Open Watcom's `wlink DEBUG ALL`
option. It is the Watcom equivalent of a PDB file.

The debug section structure (from `open-watcom-v2/bld/watcom/h/wdbginfo.h`):

```
[end of LE data pages]
[Section blocks]
  [SectionDbgHeader]   mod_offset, gbl_offset, addr_offset, section_size
  [Module info blocks]     source file names, language, line/type counts
  [Global symbol blocks]   name, segment, offset, kind (code/data/static)
  [Address info blocks]    module → code region mappings (for line numbers)
[Language table]
[Segment address table]
[MasterDbgHeader]     ← last 14 bytes of file
  signature=0x8386, versions, table sizes, total debug_size
```

The parser must expose:

```python
@dataclass
class WatcomSymbol:
    name: str          # demangled display name
    raw_name: str      # original mangled name (used for matching)
    segment: int       # 1-based LE object index
    offset: int        # offset within that object
    is_code: bool
    is_data: bool
    is_static: bool
    module_index: int | None
    calling_convention: str | None

@dataclass
class WatcomModule:
    index: int
    name: str          # full source path as recorded by the compiler
    language: str

@dataclass
class WatcomLineEntry:
    line: int
    module_index: int
    code_offset: int   # flat offset into the code object

@dataclass
class WatcomDebugInfo:
    symbols: list[WatcomSymbol]
    modules: list[WatcomModule]
    line_numbers: list[WatcomLineEntry]  # already resolved to flat offsets
```

Watcom name mangling for x86 (`__watcall` calling convention):
- Code (functions): `name_` (trailing underscore)
- Data (globals): `_name` (leading underscore)
- Static symbols and C++ names use different patterns; the demangler must handle them.

The parser is a self-contained port of the logic already implemented in the Caesar II
project. It has no dependencies beyond the Python standard library.

#### Tier 5 tests — `tests/test_watcom_debug.py`

This tier is **fully independent**: it does not require any other tier, any real binary
file, or any `LXImage`. Tests pass synthetic byte blobs directly to the parser.

Construct minimal valid Watcom debug info byte strings by hand for each test case.
The format is simple enough that a single `build_watcom_debug()` helper in the test file
can assemble the required headers and symbol records for a given set of inputs.

| Test | What it verifies |
|------|-----------------|
| `test_parse_empty` | Zero-symbol debug section parses without error |
| `test_parse_code_symbol` | Code symbol decoded with correct name, segment, offset |
| `test_parse_data_symbol` | Data symbol decoded with correct name, segment, offset |
| `test_parse_static_symbol` | Static flag parsed and exposed correctly |
| `test_watcall_demangle_code` | `foo_` → display name `foo`, raw_name `foo_` |
| `test_watcall_demangle_data` | `_bar` → display name `bar`, raw_name `_bar` |
| `test_parse_modules` | Module names and language IDs extracted |
| `test_parse_line_numbers` | Line entries resolve to correct flat offsets |
| `test_invalid_signature` | Non-`0x8386` signature raises a clear error |

---

### Tier 6 — `reccmp/compare/ingest.py`: Watcom ingestion path

These four functions are the counterparts to `load_cvdump` / `load_cvdump_lines` for
Watcom/LE targets. They populate `EntityDb` and `LinesDb` from Watcom debug info rather
than a PDB file.

#### 6.1 `load_watcom_debug(watcom_info, db, bin: LXImage, image_id: ImageId)`

For each global symbol in `watcom_info.symbols`:
- Compute absolute virtual address:
  `bin.sections[sym.segment - 1].virtual_address + sym.offset`
- Call `batch.set(image_id, addr, type=EntityType.FUNCTION or DATA,
  name=sym.name, symbol=sym.raw_name, size=...)`
- Function sizes: sort symbols by address and use the gap to the next symbol, same
  as reccmp already does for PDB symbols.
- Static symbols: load with `static_var=True` where applicable.

#### 6.2 `load_watcom_lines(watcom_info, lines_db, bin: LXImage)`

For each entry in `watcom_info.line_numbers`:
- Compute absolute virtual address from `code_object.virtual_address + entry.code_offset`
- Call `lines_db.add_lines(module_name, [(line_number, abs_addr)])`

This enables `compare_function()` to emit source file and line-number annotations
alongside the ASM diff, identical to what the existing PDB path provides.

#### 6.3 `load_watcom_map(map_file, db, code_base_addr, image_id: ImageId)`

A lightweight alternative ingestion path for the recompiled binary when the full Watcom
debug info isn't available, or as a cross-check. wlink emits `.map` files with lines of
the form:

```
 0001:00XXXXXX       _symbolname
```

Parse these, compute `abs_addr = code_base_addr + int(hex_offset, 16)`, and populate
`EntityDb` with `batch.set(image_id, abs_addr, type=EntityType.FUNCTION, symbol=name)`.

#### 6.4 `match_watcom_symbols(db)`

After loading ORIG and RECOMP sides, join them by the `symbol` field (raw Watcom mangled
name). Since Watcom preserves mangled names identically in both the embedded debug info
and the `.map` file, this is a simple string-equality match. Call
`batch.match(orig_addr, recomp_addr)` for each pair found.

This replaces `match_symbols()` + `match_functions()`, which rely on MSVC-specific name
mangling heuristics and PDB truncation behaviour.

#### 6.5 `load_markers` — relax `PEImage` type hint to `Image`

`load_markers` only uses `orig_bin.is_valid_vaddr()` (which calls `seek()`, implemented
in Tier 1.2) and `orig_bin.imagebase` (now on the base class). Change the type hint from
`PEImage` to `Image`.

#### Tier 6 tests — `tests/test_compare_ingest_watcom.py`

These tests mock out `LXImage` where needed and use synthetic `WatcomDebugInfo` objects
from Tier 5. No real binary files required.

| Test | What it verifies |
|------|-----------------|
| `test_load_watcom_debug_function` | Code symbol → `EntityType.FUNCTION` at correct VA |
| `test_load_watcom_debug_data` | Data symbol → `EntityType.DATA` at correct VA |
| `test_load_watcom_debug_static` | Static symbol → entity with `static_var=True` |
| `test_load_watcom_debug_size_from_gap` | Function size derived from next symbol offset |
| `test_load_watcom_lines` | Line entries land in `LinesDb` at correct virtual addresses |
| `test_load_watcom_map_basic` | `.map` content → correct addresses and symbols in DB |
| `test_load_watcom_map_wrong_segment` | Non-`0001:` lines are skipped |
| `test_match_watcom_symbols_match` | Identical raw names on ORIG+RECOMP sides get matched |
| `test_match_watcom_symbols_no_match` | Different raw names are not matched |
| `test_load_markers_accepts_lximage` | `load_markers` no longer crashes with a non-`PEImage` |

Regression: all existing `test_compare_ingest_cvdump.py` tests must pass unchanged.

---

### Tier 7 — `reccmp/compare/core.py`: Dispatch by image type, add Watcom path

#### 7.1 Do not remove the PE guard — replace it with type dispatch

The existing guard in `Compare.run()`:

```python
if not isinstance(self.orig_bin, PEImage) or not isinstance(
    self.recomp_bin, PEImage
):
    return
```

must **not** simply be deleted. The body of `run()` calls `match_entry(db, orig_bin,
recomp_bin)`, which would fail on a non-PE image because `RawImage` (used in many
existing tests as a mock image) does not implement `entry`. Deleting the guard without
first ensuring that all downstream calls are safe would break `test_compare_init.py`.

Instead, convert `run()` to dispatch by image type:

```python
def run(self):
    if isinstance(self.orig_bin, PEImage) and isinstance(self.recomp_bin, PEImage):
        self._run_pe()
    elif isinstance(self.orig_bin, LXImage) and isinstance(self.recomp_bin, LXImage):
        self._run_watcom()
    # else: no-op for unknown image type combinations (e.g. RawImage in tests)
```

Move the existing body of `run()` into `_run_pe()` unchanged. Write `_run_watcom()` as
the new Watcom pipeline (described below). `from_target()` is unchanged — it produces
`PEImage` instances and calls `run()` which dispatches to `_run_pe()`.

#### 7.2 `_run_watcom()` method

The Watcom pipeline, called from `run()` for LXImage pairs:

1. Call `load_watcom_debug(orig_debug_info, db, orig_bin, ImageId.ORIG)`.
2. Call `load_watcom_debug(recomp_debug_info, db, recomp_bin, ImageId.RECOMP)` if the
   recompiled binary has debug info, or `load_watcom_map(map_file, db, code_base, ImageId.RECOMP)`
   if only a `.map` file is available.
3. Call `load_watcom_lines` for both binaries.
4. Call `match_watcom_symbols(db)`.
5. Call `load_markers(code_files, ...)` for source-code annotations (optional; works
   alongside debug-info matching).
6. Call `create_imports(db, img_id, binfile)` for each binary (already generic).
7. Call `create_analysis_floats(db, img_id, binfile)` for each binary (now generic after Tier 4).
8. Call `complete_partial_floats` and `complete_partial_strings` (both generic).
9. Skip all MSVC-specific passes: `load_cvdump_types`, `match_vtables`,
   `match_static_variables`, `create_thunks`, `match_exports`,
   `create_analysis_vtordisps`, `create_seh_entities`.

#### 7.3 `Compare.from_watcom_target(target: RecCmpTarget)` classmethod

Parallel to `from_target()` but using the Watcom pipeline:

1. Load original binary:
   - If outer MZ `e_lfanew` → `LE`: call `detect_image()` → `LXImage`.
   - If outer MZ `e_lfanew` → `BW` (DOS/4GW Pro): walk BW chain, find inner MZ, and
     call `LXImage.from_memory(data, inner_mz, filepath)` directly.
2. Load recompiled binary via `detect_image()` → `LXImage` (wlink output is always
   plain MZ → LE).
3. Read Watcom debug info from both binaries (the debug section is appended to the end
   of the LE file and does not interfere with `detect_image()`).
4. Construct the `Compare` object and call `run()`, which dispatches to `_run_watcom()`.

#### Tier 7 tests

Add to `tests/test_compare_init.py`:

| Test | What it verifies |
|------|-----------------|
| `test_run_dispatches_pe` | `Compare.run()` with two `PEImage` mocks calls `_run_pe` |
| `test_run_dispatches_le` | `Compare.run()` with two `LXImage` instances calls `_run_watcom` |
| `test_run_unknown_type_noop` | `Compare.run()` with `RawImage` (neither PE nor LX) does nothing and does not raise |

Regression: `test_nested_paths` in `test_compare_init.py` uses `RawImage` via a patched
`detect_image`. After this change, `run()` hits the no-op branch for `RawImage` pairs
instead of the PE guard. The test's assertions about `c.code_files` do not depend on
`run()` having executed any analysis, so it must continue to pass.

---

### Tier 8 — `reccmp/project/`: Make PDB optional, add map file support

Open Watcom's `wlink` does not produce `.pdb` files. The project config system currently
requires a PDB path for every target.

#### 8.1 `project/config.py` — `BuildFileTarget.pdb` optional

Change `pdb: Path` to `pdb: Path | None = None`. Add `map_file: Path | None = None`.
Validation: a `BuildFileTarget` must have either `pdb` or `map_file` (or both) set.

#### 8.2 `project/detect.py` — `RecCmpTarget.recompiled_pdb` optional

Change `recompiled_pdb: Path` from a required field to `recompiled_pdb: Path | None = None`.
Add `recompiled_map: Path | None = None`. Update `RecCmpProject.get()` to pass
validation when `recompiled_pdb is None` and `recompiled_map is not None`.

#### 8.3 `project/detect.py` — detect `.map` files alongside recompiled binaries

In `detect_project(DetectWhat.RECOMPILED)`, when scanning for the binary:
1. If a `.pdb` exists next to the binary, populate `recompiled_pdb` as before.
2. Else if a `.map` exists next to the binary, populate `recompiled_map` and warn that
   only map-file-level symbol resolution will be available.
3. Else warn that neither was found.

#### 8.4 `project/detect.py` — `--paths` CLI arg: PDB/map is optional

Change the `--paths` argument group so the fourth positional (currently `<recompiled-pdb>`)
accepts either a `.pdb` or a `.map` file, detected by extension. Update
`RecCmpPathsAction` accordingly.

#### Tier 8 tests

Add to `tests/test_project_yml.py` and `tests/test_project.py`:

| Test | What it verifies |
|------|-----------------|
| `test_build_target_with_pdb` | Existing YAML with `pdb:` still loads correctly |
| `test_build_target_with_map` | YAML with `map_file:` and no `pdb:` loads correctly |
| `test_build_target_neither` | YAML with neither `pdb:` nor `map_file:` raises a validation error |
| `test_reccmp_target_optional_pdb` | `RecCmpTarget` can be constructed with `recompiled_pdb=None` and `recompiled_map` set |
| `test_project_get_fails_without_symbols` | `RecCmpProject.get()` raises `IncompleteReccmpTargetError` if both `pdb` and `map_file` are absent |
| `test_detect_finds_map_file` | In `DetectWhat.RECOMPILED` mode, a `.map` next to the binary is detected when no `.pdb` exists |

Regression: all existing `test_project_yml.py` and `test_project.py` tests must pass.
The change to `recompiled_pdb` from required to optional must not silently drop existing
YAML files that specify a PDB.

---

## Source annotation integration

reccmp's annotation comment syntax works unchanged for LE/Watcom targets. A source file
in a Watcom decompilation project annotates functions identically to any other reccmp
project:

```c
// FUNCTION: C2 0x00012345
void some_function(void)
{
    /* decompiled implementation */
}
```

Where `C2` is the target ID defined in `reccmp-project.yml`. The annotation parser
(`reccmp/parser/`) requires no changes.

The one external task for a calling project: the decomp scaffold generator should emit
`// FUNCTION: <TARGET> 0xADDR` comments above each generated function stub. This is the
standard reccmp way of declaring "this address is now implemented," and it enables
`reccmp-decomplint` to lint for duplicates and invalid addresses.

---

## What stays outside reccmp

The following items are specific to DOS/4GW Pro and belong in the calling project's own
codebase, not in reccmp:

- **BW chain walking**: parsing the `BW` stub headers to locate the inner MZ offset. The
  reccmp codebase documents that `detect_image()` handles plain DOS/4GW and that
  DOS/4GW Pro callers must resolve the inner MZ themselves before calling
  `LXImage.from_memory()`.
- **LE fixup record extraction for the decomp scaffold**: generating per-module `.asm`/`.c`
  files with fixup-aware byte sequences is project-specific tooling.
- **Ghidra import scripts** and project-specific Ghidra tooling.

---

## Dependency on implementation order

```
Compile hello_plain.exe + hello_pro.exe  ←── prerequisite: done, binaries committed
  │
  ├─▶ Tier 5 (Watcom debug parser)           ←── fully independent, no other tier needed
  │
  └─▶ Tier 1 (LXImage complete)
          └─▶ Tier 2 (detect_image comment)
          └─▶ Tier 3 (Image base class properties)
                └─▶ Tier 4 (analysis guards/generalizations)
                └─▶ Tier 6 (ingest functions)     ←── also requires Tier 5
                      └─▶ Tier 7 (Compare dispatch + _run_watcom)
                            └─▶ Tier 8 (project config changes)
```

Tier 5 can be written and tested before any other implementation tier. Every tier from 1
onwards has a self-contained test suite that exercises only the code introduced in that
tier and confirms that no previously passing tests regress.
