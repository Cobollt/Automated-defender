import zipfile
from pathlib import Path

from application.scanner_service import (
    ScannerService,
)
from domain.enums import (
    RiskLevel,
    ScanStatus,
    ThreatType,
)


def test_top_level_rar_is_not_scanned_as_normal_file(
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

    result = (
        ScannerService()
        .scan(
            archive_path
        )
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert (
        result.error_message
        is None
    )

    assert (
        result.total_files_checked
        == 0
    )

    assert (
        result.file_results
        == []
    )

    assert any(
        threat.threat_type
        == (
            ThreatType
            .UNSUPPORTED_ARCHIVE
        )
        for threat
        in result.archive_threats
    )

    assert (
        result.risk_level
        == RiskLevel.LOW
    )


def test_top_level_7zip_is_not_scanned_as_normal_file(
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

    result = (
        ScannerService()
        .scan(
            archive_path
        )
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert (
        result.total_files_checked
        == 0
    )

    assert any(
        threat.threat_type
        == (
            ThreatType
            .UNSUPPORTED_ARCHIVE
        )
        for threat
        in result.archive_threats
    )


def test_fake_rar_extension_becomes_unknown_format(
    tmp_path: Path,
) -> None:
    archive_path = (
        tmp_path
        / "fake.rar"
    )

    archive_path.write_text(
        "not a rar archive",
        encoding="utf-8",
    )

    result = (
        ScannerService()
        .scan(
            archive_path
        )
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert (
        result.total_files_checked
        == 0
    )

    assert any(
        threat.threat_type
        == ThreatType.UNKNOWN_FORMAT
        for threat
        in result.archive_threats
    )


def test_nested_unsupported_archive_is_reported_without_failure(
    tmp_path: Path,
) -> None:
    rar_path = (
        tmp_path
        / "inner.rar"
    )

    rar_path.write_bytes(
        b"Rar!\x1a\x07\x01\x00"
        + b"\x00" * 100
    )

    outer_path = (
        tmp_path
        / "outer.zip"
    )

    with zipfile.ZipFile(
        outer_path,
        "w",
    ) as archive:
        archive.write(
            rar_path,
            arcname=(
                "archives/inner.rar"
            ),
        )

        archive.writestr(
            "safe.txt",
            "safe text",
        )

    result = (
        ScannerService()
        .scan(
            outer_path
        )
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert (
        result.error_message
        is None
    )

    assert any(
        (
            threat.threat_type
            == (
                ThreatType
                .UNSUPPORTED_ARCHIVE
            )
        )
        and (
            threat.relative_path
            == "archives/inner.rar"
        )
        for threat
        in result.archive_threats
    )

    assert any(
        (
            threat.threat_type
            == (
                ThreatType
                .NESTED_ARCHIVE
            )
        )
        and (
            threat.relative_path
            == "archives/inner.rar"
        )
        for threat
        in result.archive_threats
    )

    assert any(
        file_result.relative_path
        == "safe.txt"
        for file_result
        in result.file_results
    )


def test_custom_archive_does_not_make_scan_fail(
    tmp_path: Path,
) -> None:
    archive_path = (
        tmp_path
        / "archive.custom"
    )

    archive_path.write_bytes(
        b"CSTM"
        + b"\x00" * 100
    )

    result = (
        ScannerService()
        .scan(
            archive_path
        )
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert (
        result.error_message
        is None
    )

    assert (
        result.total_files_checked
        == 0
    )

    assert any(
        threat.threat_type
        == (
            ThreatType
            .UNSUPPORTED_ARCHIVE
        )
        for threat
        in result.archive_threats
    )


def test_renamed_rar_is_still_treated_as_archive(
    tmp_path: Path,
) -> None:
    archive_path = (
        tmp_path
        / "picture.dat"
    )

    archive_path.write_bytes(
        b"Rar!\x1a\x07\x01\x00"
        + b"\x00" * 100
    )

    result = (
        ScannerService()
        .scan(
            archive_path
        )
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert (
        result.total_files_checked
        == 0
    )

    assert any(
        threat.threat_type
        == (
            ThreatType
            .UNSUPPORTED_ARCHIVE
        )
        for threat
        in result.archive_threats
    )