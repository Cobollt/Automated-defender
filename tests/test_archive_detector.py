import zipfile
from pathlib import Path

from domain.enums import ThreatType
from infrastructure.archive_detector import (
    ArchiveDetector,
)
from infrastructure.archive_readers.custom_archive_reader import (
    CustomArchiveReader,
)
from infrastructure.archive_readers.tar_reader import (
    TarArchiveReader,
)
from infrastructure.archive_readers.zip_reader import (
    ZipArchiveReader,
)


def create_detector() -> ArchiveDetector:
    return ArchiveDetector(
        [
            ZipArchiveReader(),
            TarArchiveReader(),
            CustomArchiveReader(),
        ]
    )


def test_valid_zip_has_reader(
    tmp_path: Path,
) -> None:
    archive_path = (
        tmp_path
        / "archive.zip"
    )

    with zipfile.ZipFile(
        archive_path,
        "w",
    ) as archive:
        archive.writestr(
            "file.txt",
            "test",
        )

    detector = create_detector()

    assert (
        detector.get_reader(
            archive_path
        )
        is not None
    )

    assert (
        detector.is_archive(
            archive_path
        )
        is True
    )

    assert (
        detector.is_archive_candidate(
            archive_path
        )
        is True
    )


def test_rar_signature_is_archive_candidate_without_reader(
    tmp_path: Path,
) -> None:
    archive_path = (
        tmp_path
        / "archive.rar"
    )

    archive_path.write_bytes(
        b"Rar!\x1a\x07\x01\x00"
        + b"\x00" * 100
    )

    detector = create_detector()

    assert (
        detector.get_reader(
            archive_path
        )
        is None
    )

    assert (
        detector.is_archive_candidate(
            archive_path
        )
        is True
    )

    threat = (
        detector
        .get_unhandled_archive_threat(
            archive_path
        )
    )

    assert threat is not None

    assert (
        threat.threat_type
        == (
            ThreatType
            .UNSUPPORTED_ARCHIVE
        )
    )


def test_7zip_signature_is_archive_candidate_without_reader(
    tmp_path: Path,
) -> None:
    archive_path = (
        tmp_path
        / "archive.7z"
    )

    archive_path.write_bytes(
        b"7z\xbc\xaf\x27\x1c"
        + b"\x00" * 100
    )

    detector = create_detector()

    threat = (
        detector
        .get_unhandled_archive_threat(
            archive_path
        )
    )

    assert threat is not None

    assert (
        threat.threat_type
        == (
            ThreatType
            .UNSUPPORTED_ARCHIVE
        )
    )


def test_gzip_signature_without_tar_reader_support_is_unhandled(
    tmp_path: Path,
) -> None:
    archive_path = (
        tmp_path
        / "single.gz"
    )

    archive_path.write_bytes(
        b"\x1f\x8b"
        + b"\x00" * 100
    )

    detector = create_detector()

    assert (
        detector.is_archive_candidate(
            archive_path
        )
        is True
    )

    threat = (
        detector
        .get_unhandled_archive_threat(
            archive_path
        )
    )

    assert threat is not None

    assert (
        threat.threat_type
        == (
            ThreatType
            .UNSUPPORTED_ARCHIVE
        )
    )


def test_fake_archive_extension_is_unknown_format(
    tmp_path: Path,
) -> None:
    archive_path = (
        tmp_path
        / "fake.rar"
    )

    archive_path.write_text(
        "not an archive",
        encoding="utf-8",
    )

    detector = create_detector()

    threat = (
        detector
        .get_unhandled_archive_threat(
            archive_path
        )
    )

    assert threat is not None

    assert (
        threat.threat_type
        == ThreatType.UNKNOWN_FORMAT
    )


def test_normal_text_is_not_archive_candidate(
    tmp_path: Path,
) -> None:
    file_path = (
        tmp_path
        / "file.txt"
    )

    file_path.write_text(
        "normal text",
        encoding="utf-8",
    )

    detector = create_detector()

    assert (
        detector.is_archive_candidate(
            file_path
        )
        is False
    )

    assert (
        detector
        .get_unhandled_archive_threat(
            file_path
        )
        is None
    )


def test_renamed_rar_is_detected_by_signature(
    tmp_path: Path,
) -> None:
    file_path = (
        tmp_path
        / "file.bin"
    )

    file_path.write_bytes(
        b"Rar!\x1a\x07\x01\x00"
        + b"\x00" * 100
    )

    detector = create_detector()

    threat = (
        detector
        .get_unhandled_archive_threat(
            file_path
        )
    )

    assert threat is not None

    assert (
        threat.threat_type
        == (
            ThreatType
            .UNSUPPORTED_ARCHIVE
        )
    )