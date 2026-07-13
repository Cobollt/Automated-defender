import zipfile
from pathlib import Path

from domain.enums import ThreatType
from infrastructure.archive_detector import ArchiveDetector
from infrastructure.archive_readers.zip_reader import (
    ZipArchiveReader,
)
from infrastructure.safe_extractor import SafeExtractor


def create_extractor() -> SafeExtractor:
    detector = ArchiveDetector(
        readers=[ZipArchiveReader()]
    )

    return SafeExtractor(detector)


def test_safe_zip_is_extracted(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "safe.zip"
    destination = tmp_path / "extracted"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "folder/file.txt",
            "safe content",
        )

    extractor = create_extractor()

    files = extractor.extract(
        archive_path,
        destination,
    )

    assert len(files) == 1
    assert files[0].exists()
    assert files[0].read_text(
        encoding="utf-8"
    ) == "safe content"


def test_zip_slip_path_is_detected(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "unsafe.zip"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "../outside.txt",
            "danger",
        )

    threats = create_extractor().inspect_archive(
        archive_path
    )

    assert any(
        threat.threat_type == ThreatType.UNSAFE_PATH
        for threat in threats
    )


def test_zip_slip_file_is_not_extracted(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "unsafe.zip"
    destination = tmp_path / "extracted"
    outside_path = tmp_path / "outside.txt"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "../outside.txt",
            "danger",
        )
        archive.writestr(
            "safe.txt",
            "safe",
        )

    files = create_extractor().extract(
        archive_path,
        destination,
    )

    assert not outside_path.exists()
    assert len(files) == 1
    assert files[0].name == "safe.txt"


def test_archive_detector_uses_file_signature(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "archive.unknown"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "file.txt",
            "content",
        )

    detector = ArchiveDetector(
        readers=[ZipArchiveReader()]
    )

    assert detector.is_archive(archive_path)