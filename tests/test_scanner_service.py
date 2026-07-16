import zipfile
from pathlib import Path

from application.scanner_service import ScannerService
from domain.enums import RiskLevel, ScanStatus


def test_scanner_checks_single_safe_file(
    safe_text_file: Path,
) -> None:
    scanner = ScannerService()

    result = scanner.scan(safe_text_file)

    assert result.status == ScanStatus.COMPLETED
    assert result.error_message is None

    assert result.target_path == safe_text_file
    assert result.target_sha256

    assert result.total_files_checked == 1
    assert result.total_threats_found == 0

    assert result.risk_score == 0
    assert result.risk_level == RiskLevel.SAFE

    assert len(result.file_results) == 1

    file_result = result.file_results[0]

    assert file_result.file_path == safe_text_file
    assert file_result.relative_path == safe_text_file.name
    assert file_result.sha256 == result.target_sha256


def test_scanner_returns_failure_for_missing_file(
    tmp_path: Path,
) -> None:
    missing_file = tmp_path / "missing.zip"

    result = ScannerService().scan(missing_file)

    assert result.status == ScanStatus.FAILED
    assert result.error_message is not None

    assert result.target_sha256 is None
    assert result.total_files_checked == 0
    assert result.file_results == []


def test_scanner_checks_files_inside_zip_archive(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "files.zip"

    with zipfile.ZipFile(
        archive_path,
        "w",
    ) as archive:
        archive.writestr(
            "safe.txt",
            "hello",
        )

        archive.writestr(
            "folder/danger.ps1",
            "powershell -EncodedCommand test",
        )

    result = ScannerService().scan(
        archive_path
    )

    assert result.status == ScanStatus.COMPLETED
    assert result.error_message is None

    assert result.target_sha256
    assert result.total_files_checked == 2
    assert result.total_threats_found > 0
    assert result.risk_score > 0
    assert result.risk_level != RiskLevel.SAFE

    relative_paths = {
        file_result.relative_path
        for file_result in result.file_results
    }

    assert "safe.txt" in relative_paths
    assert "folder/danger.ps1" in relative_paths

    assert all(
        file_result.relative_path is not None
        for file_result in result.file_results
    )

    assert all(
        not file_result.relative_path.startswith(
            "/tmp/"
        )
        for file_result in result.file_results
        if file_result.relative_path
    )


def test_scanner_detects_nested_archive(
    tmp_path: Path,
) -> None:
    inner_archive = tmp_path / "inner.zip"

    with zipfile.ZipFile(
        inner_archive,
        "w",
    ) as archive:
        archive.writestr(
            "danger.cmd",
            "cmd.exe powershell",
        )

    outer_archive = tmp_path / "outer.zip"

    with zipfile.ZipFile(
        outer_archive,
        "w",
    ) as archive:
        archive.write(
            inner_archive,
            arcname="archives/inner.zip",
        )

    result = ScannerService().scan(
        outer_archive
    )

    assert result.status == ScanStatus.COMPLETED
    assert result.target_sha256

    assert any(
        threat.relative_path
        == "archives/inner.zip"
        for threat in result.archive_threats
    )

    assert any(
        file_result.relative_path
        == "archives/inner.zip!/danger.cmd"
        for file_result in result.file_results
    )

    assert result.total_files_checked == 1
    assert result.total_threats_found > 0


def test_scanner_detects_unsafe_archive_path(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "unsafe.zip"

    with zipfile.ZipFile(
        archive_path,
        "w",
    ) as archive:
        archive.writestr(
            "../outside.txt",
            "danger",
        )

        archive.writestr(
            "safe.txt",
            "safe",
        )

    result = ScannerService().scan(
        archive_path
    )

    assert result.status == ScanStatus.COMPLETED

    assert any(
        "Unsafe archive path"
        in threat.description
        for threat in result.archive_threats
    )

    assert result.total_files_checked == 1

    assert any(
        file_result.relative_path == "safe.txt"
        for file_result in result.file_results
    )

    assert all(
        file_result.relative_path
        != "../outside.txt"
        for file_result in result.file_results
    )


def test_scanner_preserves_archive_member_paths(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "structure.zip"

    with zipfile.ZipFile(
        archive_path,
        "w",
    ) as archive:
        archive.writestr(
            "folder/subfolder/file.txt",
            "content",
        )

    result = ScannerService().scan(
        archive_path
    )

    assert result.status == ScanStatus.COMPLETED
    assert result.total_files_checked == 1

    file_result = result.file_results[0]

    assert (
        file_result.relative_path
        == "folder/subfolder/file.txt"
    )

    assert "/tmp/" not in file_result.relative_path
    assert "anti_archive_scanner_" not in file_result.relative_path


def test_target_sha256_differs_for_different_files(
    tmp_path: Path,
) -> None:
    first_file = tmp_path / "first.txt"
    second_file = tmp_path / "second.txt"

    first_file.write_text(
        "first",
        encoding="utf-8",
    )

    second_file.write_text(
        "second",
        encoding="utf-8",
    )

    scanner = ScannerService()

    first_result = scanner.scan(first_file)
    second_result = scanner.scan(second_file)

    assert first_result.target_sha256
    assert second_result.target_sha256

    assert (
        first_result.target_sha256
        != second_result.target_sha256
    )