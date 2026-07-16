import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from config import AppConfig
from domain.enums import ThreatType
from infrastructure.archive_detector import ArchiveDetector
from infrastructure.archive_readers.tar_reader import TarArchiveReader
from infrastructure.archive_readers.zip_reader import ZipArchiveReader
from infrastructure.safe_extractor import SafeExtractor


def create_extractor() -> SafeExtractor:
    detector = ArchiveDetector(
        readers=[
            ZipArchiveReader(),
            TarArchiveReader(),
        ]
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
    assert files[0].relative_to(destination).as_posix() == (
        "folder/file.txt"
    )

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


def test_archive_detector_uses_zip_signature(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "archive.unknown"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "file.txt",
            "content",
        )

    detector = ArchiveDetector(
        readers=[
            ZipArchiveReader(),
            TarArchiveReader(),
        ]
    )

    assert detector.is_archive(archive_path)


def test_safe_tar_is_extracted(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "safe.tar"
    destination = tmp_path / "extracted"

    content = b"safe tar content"

    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo(
            name="folder/file.txt"
        )
        member.size = len(content)

        archive.addfile(
            member,
            io.BytesIO(content),
        )

    files = create_extractor().extract(
        archive_path,
        destination,
    )

    assert len(files) == 1
    assert files[0].exists()
    assert files[0].relative_to(destination).as_posix() == (
        "folder/file.txt"
    )
    assert files[0].read_bytes() == content


def test_tar_unsafe_path_is_detected(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "unsafe.tar"

    content = b"danger"

    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo(
            name="../outside.txt"
        )
        member.size = len(content)

        archive.addfile(
            member,
            io.BytesIO(content),
        )

    threats = create_extractor().inspect_archive(
        archive_path
    )

    assert any(
        threat.threat_type == ThreatType.UNSAFE_PATH
        for threat in threats
    )


def test_tar_symbolic_link_is_detected(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "symlink.tar"

    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo(
            name="link"
        )
        member.type = tarfile.SYMTYPE
        member.linkname = "../../outside.txt"

        archive.addfile(member)

    threats = create_extractor().inspect_archive(
        archive_path
    )

    assert any(
        threat.threat_type == ThreatType.UNSAFE_PATH
        and "link" in threat.description.lower()
        for threat in threats
    )


def test_tar_symbolic_link_is_not_extracted(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "symlink.tar"
    destination = tmp_path / "extracted"

    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo(
            name="link"
        )
        member.type = tarfile.SYMTYPE
        member.linkname = "../../outside.txt"

        archive.addfile(member)

    files = create_extractor().extract(
        archive_path,
        destination,
    )

    assert files == []
    assert not (destination / "link").exists()


def test_zip_too_many_files_is_detected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        AppConfig,
        "MAX_FILES_IN_ARCHIVE",
        2,
    )

    archive_path = tmp_path / "many.zip"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("one.txt", "1")
        archive.writestr("two.txt", "2")
        archive.writestr("three.txt", "3")

    threats = create_extractor().inspect_archive(
        archive_path
    )

    assert any(
        threat.threat_type
        == ThreatType.ARCHIVE_BOMB_RISK
        and "too many" in threat.description.lower()
        for threat in threats
    )


def test_tar_too_many_files_is_detected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        AppConfig,
        "MAX_FILES_IN_ARCHIVE",
        1,
    )

    archive_path = tmp_path / "many.tar"

    with tarfile.open(archive_path, "w") as archive:
        for name in ("one.txt", "two.txt"):
            content = name.encode("utf-8")
            member = tarfile.TarInfo(name=name)
            member.size = len(content)

            archive.addfile(
                member,
                io.BytesIO(content),
            )

    threats = create_extractor().inspect_archive(
        archive_path
    )

    assert any(
        threat.threat_type
        == ThreatType.ARCHIVE_BOMB_RISK
        and "too many" in threat.description.lower()
        for threat in threats
    )


def test_zip_declared_size_limit_is_detected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        AppConfig,
        "MAX_EXTRACTED_SIZE_MB",
        0,
    )

    archive_path = tmp_path / "large.zip"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "file.txt",
            "content",
        )

    threats = create_extractor().inspect_archive(
        archive_path
    )

    assert any(
        threat.threat_type
        == ThreatType.ARCHIVE_BOMB_RISK
        and "size" in threat.description.lower()
        for threat in threats
    )


def test_tar_declared_size_limit_is_detected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        AppConfig,
        "MAX_EXTRACTED_SIZE_MB",
        0,
    )

    archive_path = tmp_path / "large.tar"
    content = b"content"

    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo(
            name="file.txt"
        )
        member.size = len(content)

        archive.addfile(
            member,
            io.BytesIO(content),
        )

    threats = create_extractor().inspect_archive(
        archive_path
    )

    assert any(
        threat.threat_type
        == ThreatType.ARCHIVE_BOMB_RISK
        and "size" in threat.description.lower()
        for threat in threats
    )


def test_zip_extraction_stops_when_size_limit_is_exceeded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        AppConfig,
        "MAX_EXTRACTED_SIZE_MB",
        0,
    )

    archive_path = tmp_path / "large.zip"
    destination = tmp_path / "extracted"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "large.txt",
            "content",
        )

    with pytest.raises(
        ValueError,
        match="extracted size",
    ):
        create_extractor().extract(
            archive_path,
            destination,
        )


def test_tar_extraction_stops_when_size_limit_is_exceeded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        AppConfig,
        "MAX_EXTRACTED_SIZE_MB",
        0,
    )

    archive_path = tmp_path / "large.tar"
    destination = tmp_path / "extracted"
    content = b"content"

    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo(
            name="large.txt"
        )
        member.size = len(content)

        archive.addfile(
            member,
            io.BytesIO(content),
        )

    with pytest.raises(
        ValueError,
        match="extracted size",
    ):
        create_extractor().extract(
            archive_path,
            destination,
        )


def test_encrypted_zip_entry_is_detected(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "encrypted-flag.zip"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "file.txt",
            "content",
        )

    with zipfile.ZipFile(archive_path, "r") as archive:
        information = archive.infolist()[0]

    information.flag_bits |= 0x1

    reader = ZipArchiveReader()

    assert information.flag_bits & 0x1
    assert reader.supports(archive_path)


def test_unsupported_file_is_rejected(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "not-archive.bin"
    file_path.write_bytes(
        b"not an archive"
    )

    extractor = create_extractor()

    with pytest.raises(
        ValueError,
        match="Unsupported archive format",
    ):
        extractor.extract(
            file_path,
            tmp_path / "extracted",
        )