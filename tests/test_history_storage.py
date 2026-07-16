import json
from pathlib import Path

from domain.enums import FileAction, RiskLevel, ScanStatus
from domain.models import (
    ActionResult,
    QuarantineResult,
    ScanResult,
)
from infrastructure.history_storage import HistoryStorage


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]


def test_scan_history_saves_target_sha256_and_risk(
    tmp_path: Path,
) -> None:
    scan_history_path = tmp_path / "scan_history.jsonl"
    action_history_path = tmp_path / "action_history.jsonl"

    storage = HistoryStorage(
        scan_history_path=scan_history_path,
        action_history_path=action_history_path,
    )

    target_path = tmp_path / "archive.zip"

    scan_result = ScanResult(
        target_path=target_path,
        target_sha256="archive-sha256",
        status=ScanStatus.COMPLETED,
        risk_score=45,
        risk_level=RiskLevel.MEDIUM,
        total_files_checked=3,
        total_threats_found=2,
    )

    saved = storage.save_scan(
        result=scan_result,
        report_path=tmp_path / "report.json",
    )

    assert saved is True
    assert scan_history_path.exists()

    records = read_jsonl(scan_history_path)

    assert len(records) == 1

    record = records[0]

    assert record["record_type"] == "scan"
    assert record["target_name"] == "archive.zip"
    assert record["target_path"] == str(target_path)
    assert record["target_sha256"] == "archive-sha256"
    assert record["status"] == "completed"
    assert record["risk_score"] == 45
    assert record["risk_level"] == "medium"
    assert record["total_files_checked"] == 3
    assert record["total_threats_found"] == 2
    assert record["report_path"] == str(
        tmp_path / "report.json"
    )


def test_action_history_saves_sha256_and_risk(
    tmp_path: Path,
) -> None:
    scan_history_path = tmp_path / "scan_history.jsonl"
    action_history_path = tmp_path / "action_history.jsonl"

    storage = HistoryStorage(
        scan_history_path=scan_history_path,
        action_history_path=action_history_path,
    )

    file_path = tmp_path / "danger.exe"

    action_result = ActionResult(
        success=True,
        action=FileAction.DELETE,
        file_path=file_path,
        message="Файл удалён.",
        sha256="danger-sha256",
        risk_score=80,
        risk_level=RiskLevel.CRITICAL,
    )

    saved = storage.save_action(
        result=action_result,
    )

    assert saved is True
    assert action_history_path.exists()

    records = read_jsonl(action_history_path)

    assert len(records) == 1

    record = records[0]

    assert record["record_type"] == "action"
    assert record["file_name"] == "danger.exe"
    assert record["file_path"] == str(file_path)
    assert record["sha256"] == "danger-sha256"
    assert record["risk_score"] == 80
    assert record["risk_level"] == "critical"
    assert record["action"] == "delete"
    assert record["success"] is True
    assert record["message"] == "Файл удалён."


def test_action_history_saves_quarantine_result(
    tmp_path: Path,
) -> None:
    scan_history_path = tmp_path / "scan_history.jsonl"
    action_history_path = tmp_path / "action_history.jsonl"

    storage = HistoryStorage(
        scan_history_path=scan_history_path,
        action_history_path=action_history_path,
    )

    original_path = tmp_path / "danger.zip"
    quarantine_path = (
        tmp_path
        / "quarantine"
        / "danger.quarantine"
    )

    quarantine_result = QuarantineResult(
        success=True,
        provider_name="Test Quarantine",
        original_path=original_path,
        quarantine_path=quarantine_path,
        message="Файл изолирован.",
    )

    action_result = ActionResult(
        success=True,
        action=FileAction.QUARANTINE,
        file_path=original_path,
        message="Файл изолирован.",
        sha256="quarantine-sha256",
        risk_score=70,
        risk_level=RiskLevel.HIGH,
        quarantine_result=quarantine_result,
    )

    saved = storage.save_action(
        result=action_result,
        quarantine_result=quarantine_result,
    )

    assert saved is True

    records = read_jsonl(action_history_path)

    assert len(records) == 1

    record = records[0]

    assert record["action"] == "quarantine"
    assert record["sha256"] == "quarantine-sha256"
    assert record["risk_score"] == 70
    assert record["risk_level"] == "high"

    quarantine_record = record["quarantine"]

    assert quarantine_record["success"] is True
    assert (
        quarantine_record["provider_name"]
        == "Test Quarantine"
    )
    assert (
        quarantine_record["original_path"]
        == str(original_path)
    )
    assert (
        quarantine_record["quarantine_path"]
        == str(quarantine_path)
    )
    assert (
        quarantine_record["message"]
        == "Файл изолирован."
    )


def test_action_history_allows_missing_risk_data(
    tmp_path: Path,
) -> None:
    scan_history_path = tmp_path / "scan_history.jsonl"
    action_history_path = tmp_path / "action_history.jsonl"

    storage = HistoryStorage(
        scan_history_path=scan_history_path,
        action_history_path=action_history_path,
    )

    action_result = ActionResult(
        success=False,
        action=FileAction.KEEP,
        file_path=tmp_path / "missing.txt",
        message="Файл отсутствует.",
        sha256=None,
        risk_score=None,
        risk_level=None,
    )

    saved = storage.save_action(
        result=action_result,
    )

    assert saved is True

    record = read_jsonl(action_history_path)[0]

    assert record["sha256"] is None
    assert record["risk_score"] is None
    assert record["risk_level"] is None