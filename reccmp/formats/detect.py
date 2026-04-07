from pathlib import Path

from .elf import ElfImage
from .image import Image
from .lx import LXImage
from .macho import MachOImage
from .mz import ImageDosHeader, MZImage
from .ne import NEImage
from .pe import PEImage


def detect_image(filepath: Path | str) -> Image:
    filepath = Path(filepath)
    with filepath.open("rb") as f:
        data = f.read()
    if MZImage.taste(data, offset=0):
        mz_header, _ = ImageDosHeader.from_memory(data, offset=0)

        match data[mz_header.e_lfanew : mz_header.e_lfanew + 2]:
            case b"PE":
                return PEImage.from_memory(data, mz_header=mz_header, filepath=filepath)
            case b"LE":
                # Plain DOS/4GW (freeware): the outer MZ e_lfanew points directly at
                # the LE header.  LXImage.from_memory() defaults mz_offset=0, which
                # is correct because the MZ is at the start of the file.
                return LXImage.from_memory(data, mz_header=mz_header, filepath=filepath)
            case b"BW":
                # DOS/4GW Professional (commercial): the outer MZ e_lfanew points at
                # a BW stub (DOS/4GW Pro's protected-mode loader), not at LE directly.
                # The LE header is only reachable by walking the BW chain:
                #
                #   outer MZ  e_lfanew ──► BW #1
                #                           next_header_pos ──► BW #2
                #                                                next_header_pos ──► inner MZ
                #                                                                     e_lfanew ──► LE
                #
                # This function cannot safely walk the chain without knowing the
                # project-specific format, so it returns a plain MZImage.  Callers
                # that need an LXImage for a DOS/4GW Pro binary must walk the chain
                # themselves and call LXImage.from_memory() with the inner MZ header
                # and its file offset:
                #
                #   offset = outer_mz.e_lfanew
                #   while data[offset : offset + 2] == b"BW":
                #       offset = struct.unpack_from("<I", data, offset + 28)[0]
                #   inner_mz, _ = ImageDosHeader.from_memory(data, offset)
                #   image = LXImage.from_memory(data, inner_mz, filepath, mz_offset=offset)
                #
                return MZImage.from_memory(data, mz_header=mz_header, filepath=filepath)
            case b"NE":
                return NEImage.from_memory(data, mz_header=mz_header, filepath=filepath)
            case b"NX":
                raise NotImplementedError("NX file format not implemented")
            case _:
                return MZImage.from_memory(data, mz_header=mz_header, filepath=filepath)
    if ElfImage.taste(data, offset=0):
        return ElfImage.from_memory(data, offset=0, filepath=filepath)
    if MachOImage.taste(data, offset=0):
        return MachOImage.from_memory(data, offset=0, filepath=filepath)

    raise ValueError("Unknown file format")
