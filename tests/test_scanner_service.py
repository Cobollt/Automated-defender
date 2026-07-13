import zipfile
from pathlib import Path

from application.scanner_service import ScannerService
from domain.enums import RiskLevel, ScanStatus


def test_scanner_checks_single_file(
    safe_text_file: Path,
) -> None:
    scanner = ScannerService()

    result = scanner.scan(safe_text_file)

    assert result.status == ScanStatus.COMPLETED
    assert result.total_files_checked == 1
    assert result.risk_level == RiskLevel.SAFE
    assert result.error_message is None


def test_scanner_returns_failure_for_missing_file(
    tmp_path: Path,
) -> None:
    missing_file = tmp_path / "missing.zip"

    result = ScannerService().scan(missing_file)

    assert result.status == ScanStatus.FAILED
    assert result.error_message is not None


def test_scanner_checks_files_inside_archive(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "files.zip"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(
            "safe.txt",
            "hello",
        )
        archive.writestr(
            "danger.ps1",
            "powershell -EncodedCommand test",
        )

    result = ScannerService().scan(archive_path)

    assert result.status == ScanStatus.COMPLETED
    assert result.total_files_checked == 2
    assert result.total_threats_found > 0
    assert result.risk_score > 0