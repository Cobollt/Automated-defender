import json
from pathlib import Path

from domain.enums import RiskLevel, ScanStatus, ThreatType
from domain.models import (
    DetectedThreat,
    FileScanResult,
    ScanResult,
)
from infrastructure.report_writer import ReportWriter


def test_report_writer_creates_json_and_text_reports(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"

    target_path = tmp_path / "archive.zip"

    scan_result = ScanResult(
        target_path=target_path,
        target_sha256="archive-sha256",
        status=ScanStatus.COMPLETED,
        risk_score=45,
        risk_level=RiskLevel.MEDIUM,
        total_files_checked=2,
        total_threats_found=2,
    )

    scan_result.archive_threats.append(
        DetectedThreat(
            threat_type=ThreatType.NESTED_ARCHIVE,
            description="Nested archive detected",
            score=10,
            file_path=target_path,
            relative_path="nested.zip",
        )
    )

    scan_result.file_results.append(
        FileScanResult(
            file_path=Path(
                "/tmp/anti_archive_scanner_test/"
                "folder/danger.ps1"
            ),
            sha256="file-sha256",
            relative_path="folder/danger.ps1",
            risk_score=35,
            risk_level=RiskLevel.MEDIUM,
            threats=[
                DetectedThreat(
                    threat_type=ThreatType.SUSPICIOUS_STRING,
                    description="Suspicious string found: powershell",
                    score=15,
                    file_path=Path(
                        "/tmp/anti_archive_scanner_test/"
                        "folder/danger.ps1"
                    ),
                    relative_path="folder/danger.ps1",
                )
            ],
        )
    )

    writer = ReportWriter(
        reports_dir=reports_dir
    )

    returned_path = writer.write_scan_report(
        scan_result
    )

    assert returned_path is not None
    assert returned_path.exists()
    assert returned_path.suffix == ".json"

    json_reports = list(
        reports_dir.glob("scan_*.json")
    )

    text_reports = list(
        reports_dir.glob("scan_*.txt")
    )

    assert len(json_reports) == 1
    assert len(text_reports) == 1


def test_json_report_contains_target_sha256_and_relative_paths(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"

    scan_result = ScanResult(
        target_path=tmp_path / "archive.zip",
        target_sha256="target-sha256",
        status=ScanStatus.COMPLETED,
        risk_score=60,
        risk_level=RiskLevel.HIGH,
        total_files_checked=1,
        total_threats_found=1,
    )

    scan_result.file_results.append(
        FileScanResult(
            file_path=Path(
                "/tmp/anti_archive_scanner_example/"
                "folder/file.exe"
            ),
            sha256="inner-file-sha256",
            relative_path="folder/file.exe",
            risk_score=50,
            risk_level=RiskLevel.MEDIUM,
            threats=[
                DetectedThreat(
                    threat_type=ThreatType.EXECUTABLE_SIGNATURE,
                    description="Executable signature detected",
                    score=30,
                    file_path=Path(
                        "/tmp/anti_archive_scanner_example/"
                        "folder/file.exe"
                    ),
                    relative_path="folder/file.exe",
                )
            ],
        )
    )

    writer = ReportWriter(
        reports_dir=reports_dir
    )

    report_path = writer.write_scan_report(
        scan_result
    )

    assert report_path is not None

    data = json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )

    assert data["target"]["sha256"] == "target-sha256"

    file_result = data["file_results"][0]

    assert file_result["path"] == "folder/file.exe"
    assert file_result["sha256"] == "inner-file-sha256"
    assert file_result["risk_score"] == 50
    assert file_result["risk_level"] == "medium"

    threat = file_result["threats"][0]

    assert threat["path"] == "folder/file.exe"

    serialized_report = json.dumps(
        data,
        ensure_ascii=False,
    )

    assert "/tmp/" not in serialized_report
    assert "anti_archive_scanner_" not in serialized_report


def test_text_report_contains_main_scan_information(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"

    scan_result = ScanResult(
        target_path=tmp_path / "sample.zip",
        target_sha256="sample-sha256",
        status=ScanStatus.COMPLETED,
        risk_score=80,
        risk_level=RiskLevel.CRITICAL,
        total_files_checked=1,
        total_threats_found=1,
    )

    scan_result.file_results.append(
        FileScanResult(
            file_path=Path("/tmp/temp/file.cmd"),
            sha256="cmd-sha256",
            relative_path="scripts/file.cmd",
            risk_score=80,
            risk_level=RiskLevel.CRITICAL,
            threats=[
                DetectedThreat(
                    threat_type=ThreatType.SUSPICIOUS_EXTENSION,
                    description="Suspicious file extension: .cmd",
                    score=20,
                    file_path=Path("/tmp/temp/file.cmd"),
                    relative_path="scripts/file.cmd",
                )
            ],
        )
    )

    writer = ReportWriter(
        reports_dir=reports_dir
    )

    writer.write_scan_report(scan_result)

    text_reports = list(
        reports_dir.glob("scan_*.txt")
    )

    assert len(text_reports) == 1

    content = text_reports[0].read_text(
        encoding="utf-8"
    )

    assert "AntiArchiveScanner — отчёт проверки" in content
    assert "sample-sha256" in content
    assert "Уровень риска: critical" in content
    assert "Оценка риска: 80/100" in content
    assert "scripts/file.cmd" in content
    assert "cmd-sha256" in content

    assert "/tmp/" not in content
    assert "anti_archive_scanner_" not in content


def test_archive_threat_relative_path_is_saved(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"

    scan_result = ScanResult(
        target_path=tmp_path / "outer.zip",
        target_sha256="outer-sha256",
        status=ScanStatus.COMPLETED,
        risk_score=10,
        risk_level=RiskLevel.LOW,
        total_files_checked=0,
        total_threats_found=1,
    )

    scan_result.archive_threats.append(
        DetectedThreat(
            threat_type=ThreatType.NESTED_ARCHIVE,
            description="Nested archive detected",
            score=10,
            file_path=Path(
                "/tmp/anti_archive_scanner_test/inner.zip"
            ),
            relative_path="archives/inner.zip",
        )
    )

    writer = ReportWriter(
        reports_dir=reports_dir
    )

    report_path = writer.write_scan_report(
        scan_result
    )

    assert report_path is not None

    data = json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )

    threat = data["archive_threats"][0]

    assert threat["path"] == "archives/inner.zip"

    text_report = next(
        reports_dir.glob("scan_*.txt")
    )

    text_content = text_report.read_text(
        encoding="utf-8"
    )

    assert "archives/inner.zip" in text_content
    assert "/tmp/" not in text_content


def test_report_writer_returns_none_when_all_writes_fail(
    tmp_path: Path,
    monkeypatch,
) -> None:
    writer = ReportWriter(
        reports_dir=tmp_path / "reports"
    )

    scan_result = ScanResult(
        target_path=tmp_path / "file.txt",
        target_sha256="hash",
        status=ScanStatus.COMPLETED,
    )

    monkeypatch.setattr(
        writer,
        "_write_json_report",
        lambda report_path, report_data: False,
    )

    monkeypatch.setattr(
        writer,
        "_write_text_report",
        lambda report_path, result, report_id, generated_at: False,
    )

    result = writer.write_scan_report(
        scan_result
    )

    assert result is None