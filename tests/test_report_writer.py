import json
from pathlib import Path

from config import AppConfig
from domain.enums import (
    RiskLevel,
    ScanStatus,
    ThreatType,
)
from domain.models import (
    DetectedThreat,
    FileScanResult,
    ScanResult,
)
from infrastructure.report_writer import (
    ReportWriter,
)


def create_scan_result(
    tmp_path: Path,
) -> ScanResult:
    result = ScanResult(
        target_path=(
            tmp_path
            / "archive.zip"
        ),
        target_sha256=(
            "archive-sha256"
        ),
        status=(
            ScanStatus.COMPLETED
        ),
        risk_score=45,
        risk_level=(
            RiskLevel.MEDIUM
        ),
        total_files_checked=1,
        total_threats_found=1,
    )

    result.file_results.append(
        FileScanResult(
            file_path=Path(
                "/tmp/"
                "anti_archive_scanner_test/"
                "folder/danger.ps1"
            ),
            sha256=(
                "file-sha256"
            ),
            relative_path=(
                "folder/danger.ps1"
            ),
            risk_score=35,
            risk_level=(
                RiskLevel.MEDIUM
            ),
            threats=[
                DetectedThreat(
                    threat_type=(
                        ThreatType
                        .SUSPICIOUS_STRING
                    ),
                    description=(
                        "Suspicious string "
                        "found"
                    ),
                    score=15,
                    file_path=Path(
                        "/tmp/"
                        "anti_archive_scanner_test/"
                        "folder/danger.ps1"
                    ),
                    relative_path=(
                        "folder/danger.ps1"
                    ),
                )
            ],
        )
    )

    return result


def test_report_writer_creates_json_and_text_reports(
    tmp_path: Path,
) -> None:
    reports_dir = (
        tmp_path / "reports"
    )

    writer = ReportWriter(
        reports_dir=reports_dir
    )

    returned_path = (
        writer.write_scan_report(
            create_scan_result(
                tmp_path
            )
        )
    )

    assert (
        returned_path
        is not None
    )

    assert (
        returned_path.exists()
    )

    assert (
        returned_path.suffix
        == ".json"
    )

    assert (
        len(
            list(
                reports_dir.glob(
                    "scan_*.json"
                )
            )
        )
        == 1
    )

    assert (
        len(
            list(
                reports_dir.glob(
                    "scan_*.txt"
                )
            )
        )
        == 1
    )


def test_json_report_contains_relative_paths_only(
    tmp_path: Path,
) -> None:
    reports_dir = (
        tmp_path / "reports"
    )

    writer = ReportWriter(
        reports_dir=reports_dir
    )

    report_path = (
        writer.write_scan_report(
            create_scan_result(
                tmp_path
            )
        )
    )

    assert (
        report_path is not None
    )

    data = json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )

    assert (
        data["target"]["name"]
        == "archive.zip"
    )

    assert (
        data["target"]["path"]
        == "archive.zip"
    )

    file_result = (
        data["file_results"][0]
    )

    assert (
        file_result["path"]
        == "folder/danger.ps1"
    )

    assert (
        file_result["sha256"]
        == "file-sha256"
    )

    serialized = (
        json.dumps(
            data,
            ensure_ascii=False,
        )
    )

    assert (
        "/tmp/"
        not in serialized
    )

    assert (
        "anti_archive_scanner_"
        not in serialized
    )


def test_text_report_contains_main_scan_information(
    tmp_path: Path,
) -> None:
    reports_dir = (
        tmp_path / "reports"
    )

    result = (
        create_scan_result(
            tmp_path
        )
    )

    result.risk_score = 80

    result.risk_level = (
        RiskLevel.CRITICAL
    )

    writer = ReportWriter(
        reports_dir=reports_dir
    )

    writer.write_scan_report(
        result
    )

    text_report = next(
        reports_dir.glob(
            "scan_*.txt"
        )
    )

    content = (
        text_report.read_text(
            encoding="utf-8"
        )
    )

    assert (
        "AntiArchiveScanner — "
        "отчёт проверки"
        in content
    )

    assert (
        "archive-sha256"
        in content
    )

    assert (
        "Уровень риска: critical"
        in content
    )

    assert (
        "Оценка риска: 80/100"
        in content
    )

    assert (
        "folder/danger.ps1"
        in content
    )

    assert (
        "/tmp/"
        not in content
    )


def test_archive_threat_relative_path_is_saved(
    tmp_path: Path,
) -> None:
    result = ScanResult(
        target_path=(
            tmp_path / "outer.zip"
        ),
        target_sha256=(
            "outer-sha256"
        ),
        status=(
            ScanStatus.COMPLETED
        ),
        risk_score=10,
        risk_level=(
            RiskLevel.LOW
        ),
        total_files_checked=0,
        total_threats_found=1,
    )

    result.archive_threats.append(
        DetectedThreat(
            threat_type=(
                ThreatType
                .NESTED_ARCHIVE
            ),
            description=(
                "Nested archive detected"
            ),
            score=10,
            file_path=Path(
                "/tmp/"
                "anti_archive_scanner_test/"
                "inner.zip"
            ),
            relative_path=(
                "archives/inner.zip"
            ),
        )
    )

    reports_dir = (
        tmp_path / "reports"
    )

    report_path = (
        ReportWriter(
            reports_dir=reports_dir
        )
        .write_scan_report(
            result
        )
    )

    assert (
        report_path is not None
    )

    data = json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )

    assert (
        data[
            "archive_threats"
        ][0]["path"]
        == "archives/inner.zip"
    )

    text_content = (
        next(
            reports_dir.glob(
                "scan_*.txt"
            )
        )
        .read_text(
            encoding="utf-8"
        )
    )

    assert (
        "archives/inner.zip"
        in text_content
    )

    assert (
        "/tmp/"
        not in text_content
    )


def test_report_writer_returns_none_when_all_writes_fail(
    tmp_path: Path,
    monkeypatch,
) -> None:
    writer = ReportWriter(
        reports_dir=(
            tmp_path / "reports"
        )
    )

    result = ScanResult(
        target_path=(
            tmp_path / "file.txt"
        ),
        target_sha256="hash",
        status=(
            ScanStatus.COMPLETED
        ),
    )

    monkeypatch.setattr(
        writer,
        "_write_json_report",
        lambda *args, **kwargs: False,
    )

    monkeypatch.setattr(
        writer,
        "_write_text_report",
        lambda *args, **kwargs: False,
    )

    assert (
        writer.write_scan_report(
            result
        )
        is None
    )


def test_temporary_report_files_are_removed_after_success(
    tmp_path: Path,
) -> None:
    reports_dir = (
        tmp_path / "reports"
    )

    writer = ReportWriter(
        reports_dir=reports_dir
    )

    writer.write_scan_report(
        create_scan_result(
            tmp_path
        )
    )

    assert (
        list(
            reports_dir.glob(
                "*.tmp"
            )
        )
        == []
    )


def test_old_report_pairs_are_removed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    reports_dir = (
        tmp_path / "reports"
    )

    monkeypatch.setattr(
        AppConfig,
        "MAX_REPORT_FILES",
        2,
    )

    writer = ReportWriter(
        reports_dir=reports_dir
    )

    for _ in range(4):
        writer.write_scan_report(
            create_scan_result(
                tmp_path
            )
        )

    assert (
        len(
            list(
                reports_dir.glob(
                    "scan_*.json"
                )
            )
        )
        <= 2
    )

    assert (
        len(
            list(
                reports_dir.glob(
                    "scan_*.txt"
                )
            )
        )
        <= 2
    )