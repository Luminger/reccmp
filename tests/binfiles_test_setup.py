from typing import NamedTuple


class TestBinfile(NamedTuple):
    filename: str
    hash_str: str


BINFILE_LEGO1 = TestBinfile(
    "LEGO1.DLL", "14645225bbe81212e9bc1919cd8a692b81b8622abb6561280d99b0fc4151ce17"
)
"""LEGO1.DLL: v1.1 English, September"""

BINFILE_SKI = TestBinfile(
    "SKI.EXE", "0b97b99fcf34af5f5d624080417c79c7d36ae11351a7870ce6e0a476f03515c2"
)
"""SkiFree 1.0, https://ski.ihoc.net/"""

BINFILE_ISLE = TestBinfile(
    "ISLE.EXE", "5cf57c284973fce9d14f5677a2e4435fd989c5e938970764d00c8932ed5128ca"
)
"""ISLE.EXE: v1.1 English, September"""

BINFILE_LE_PLAIN = TestBinfile(
    "hello_plain.exe",
    "2c3d0c39e4418fda166c1e48ab46a07296d37c33af9ca718ec71596da241ca1c",
)
"""Plain DOS/4GW LE binary (MZ → LE directly).
Compiled from tests/binfiles/le_src/hello.c with Open Watcom v2.
See docs/le-format-support.md for the exact build recipe."""

BINFILE_LE_PRO = TestBinfile(
    "hello_pro.exe",
    "07fe3a8c22d7c49748e0bc60469eb2307a950c0093038d9e60b1507d865aab08",
)
"""DOS/4GW Professional LE binary (MZ → BW chain → inner MZ → LE).
Compiled from tests/binfiles/le_src/hello.c with Open Watcom v2,
using the DOS/4GW Pro stub extracted from a DOS/4GW Pro binary.
See docs/le-format-support.md for the exact build recipe."""

BINFILE_LE_WATDBG = TestBinfile(
    "hello_watdbg.exe",
    "c2e624c0fcbc6b7f81f7a88a8616cab8f13179305f7faeb2e904ef0598390059",
)
"""Plain DOS/4GW LE binary with Watcom Debug Info 3.0 appended.
Compiled from tests/binfiles/le_src/hello.c with Open Watcom v2
using -hw (Watcom debug format) and linked with DEBUG WATCOM ALL.
Provides known ground-truth values for the Watcom debug parser tests.
Build recipe:
    wcc386 -bt=dos4g -mf -3r -fpi87 -d1 -hw -fo=hello_dbg.obj hello.c
    wlink FORMAT os2 le DEBUG WATCOM ALL OPTION NODEFAULTLIBS \\
          OPTION START=_cstart_ OPTION QUIET \\
          LIBPATH $WATCOM/lib386 LIBPATH $WATCOM/lib386/dos \\
          LIB clib3r LIB math387r FILE hello_dbg.obj NAME hello_watdbg.exe"""
