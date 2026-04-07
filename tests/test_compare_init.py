"""Testing constructors of the Compare core"""

from pathlib import Path
from unittest.mock import patch
import pytest
from reccmp.compare import Compare
from reccmp.project.detect import RecCmpTarget, GhidraConfig, ReportConfig
from reccmp.cvdump.parser import CvdumpParser
from .raw_image import RawImage


@pytest.fixture(name="source_dir")
def fixture_source_dir(tmp_path_factory) -> Path:
    """Create a basic source root with files in two directories."""
    src_dir = tmp_path_factory.mktemp("src")
    (src_dir / "hello.cpp").write_text("")
    (src_dir / "hello.hpp").write_text("")
    (src_dir / "test").mkdir()
    (src_dir / "test" / "game.cpp").write_text("")
    (src_dir / "test" / "game.hpp").write_text("")

    return src_dir


def test_nested_paths(source_dir: Path):
    """Compare core will eliminate duplicate code file paths
    if the list of source paths contains any that are nested."""
    nested_paths = (source_dir, source_dir / "test")

    target = RecCmpTarget(
        target_id="TEST",
        filename="TEST.exe",
        sha256="",
        source_paths=nested_paths,
        original_path=Path("TEST.exe"),
        recompiled_path=Path("build/TEST.exe"),
        recompiled_pdb=Path("build/TEST.pdb"),
        ghidra_config=GhidraConfig(),
        report_config=ReportConfig(),
    )

    # Patch detect_image: don't open the file, just return a RawImage
    # Patch Cvdump.run: don't subprocess.run, just return an empty Cvdump result
    with (
        patch(
            "reccmp.compare.core.detect_image", new=lambda **_: RawImage.from_memory()
        ),
        patch("reccmp.compare.core.Cvdump.run", new=lambda _: CvdumpParser()),
    ):
        c = Compare.from_target(target)

        # If path walks were just combined, we would have 6 files.
        assert len(c.code_files) == 4

        # Verify that paths are sorted
        assert [f.path.name for f in c.code_files] == [
            "hello.cpp",
            "hello.hpp",
            "game.cpp",
            "game.hpp",
        ]


# ── run() dispatch ─────────────────────────────────────────────────────────────


def test_run_dispatches_pe():
    """Compare.run() with two PEImage instances calls _run_pe."""
    from unittest.mock import MagicMock, patch
    from reccmp.formats import PEImage
    from reccmp.cvdump import CvdumpAnalysis
    from reccmp.cvdump.parser import CvdumpParser

    orig = MagicMock(spec=PEImage)
    recomp = MagicMock(spec=PEImage)
    c = Compare(orig, recomp, pdb_file=CvdumpAnalysis(CvdumpParser()))

    with patch.object(c, "_run_pe") as mock_pe, patch.object(c, "_run_watcom") as mock_wt:
        c.run()
        mock_pe.assert_called_once()
        mock_wt.assert_not_called()


def test_run_dispatches_le(bin_loader):
    """Compare.run() with two LXImage instances calls _run_watcom."""
    from unittest.mock import patch
    from reccmp.formats import LXImage, detect_image
    from .binfiles_test_setup import BINFILE_LE_PLAIN

    path = bin_loader(BINFILE_LE_PLAIN, file_is_required=True)
    le = detect_image(path)
    assert isinstance(le, LXImage)

    c = Compare(le, le)

    with patch.object(c, "_run_pe") as mock_pe, patch.object(c, "_run_watcom") as mock_wt:
        c.run()
        mock_wt.assert_called_once()
        mock_pe.assert_not_called()


def test_run_unknown_type_noop():
    """Compare.run() with a RawImage (not PE or LX) is a no-op — no crash, no DB entries."""
    img = RawImage.from_memory(b"\x00" * 64)
    c = Compare(img, img)
    c.run()  # must not raise
    assert c._db.count() == 0


def test_run_watcom_with_debug_info(bin_loader):
    """_run_watcom populates the DB when Watcom debug info is available."""
    from reccmp.formats import LXImage, detect_image
    from reccmp.formats.watcom_debug import parse_watcom_debug_file
    from reccmp.types import ImageId
    from .binfiles_test_setup import BINFILE_LE_PLAIN, BINFILE_LE_WATDBG

    plain_path  = bin_loader(BINFILE_LE_PLAIN,  file_is_required=True)
    watdbg_path = bin_loader(BINFILE_LE_WATDBG, file_is_required=True)

    orig_le   = detect_image(watdbg_path)
    recomp_le = detect_image(plain_path)
    assert isinstance(orig_le, LXImage)
    assert isinstance(recomp_le, LXImage)

    debug_info = parse_watcom_debug_file(watdbg_path)

    c = Compare(orig_le, recomp_le)
    c._watcom_orig = debug_info
    c.run()

    # add_ should be loaded on the ORIG side
    e = c._db.get(ImageId.ORIG, 0x10000 + 0x10)
    assert e is not None
    assert e.get("symbol") == "add_"


def test_from_watcom_target_integration(bin_loader):
    """from_watcom_target constructs a Compare and runs _run_watcom end-to-end."""
    from reccmp.formats import LXImage
    from reccmp.types import ImageId
    from .binfiles_test_setup import BINFILE_LE_PLAIN, BINFILE_LE_WATDBG

    watdbg_path = bin_loader(BINFILE_LE_WATDBG, file_is_required=True)
    plain_path  = bin_loader(BINFILE_LE_PLAIN,  file_is_required=True)

    c = Compare.from_watcom_target(
        original_path=watdbg_path,
        recompiled_path=plain_path,
        target_id="HELLO",
    )

    assert isinstance(c.orig_bin, LXImage)
    assert isinstance(c.recomp_bin, LXImage)
    # Symbols from the original's debug info should be in the DB
    e = c._db.get(ImageId.ORIG, 0x10000 + 0x10)
    assert e is not None
    assert e.get("symbol") == "add_"
