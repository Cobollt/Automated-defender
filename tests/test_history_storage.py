import json
from pathlib import Path

from domain.enums import (
    FileAction,
    RiskLevel,
    ScanStatus,
)
from domain.models import (
    ActionResult,
    QuarantineResult,
    ScanResult,
)
from infrastructure.history_storage import (
    HistoryStorage,
)


def read_jsonl(
    path: Path,
) -> list[dict]:
    return [
        json.loads(line)
        for line
        in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]


def create_storage(
    tmp_path: Path,
) -> HistoryStorage:
    return HistoryStorage(
        scan_history_path=(
            tmp_path
            / "scan_history.jsonl"
        ),
        action_history_path=(
            tmp_path
            / "action_history.jsonl"
        ),
    )


def test_scan_history_saves_target_sha256_and_risk(
    tmp_path: Path,
) -> None:
    storage = (
        create_storage(
            tmp_path
        )
    )

    target_path = (
        tmp_path
        / "archive.zip"
    )

    result = ScanResult(
        target_path=target_path,
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
        total_files_checked=3,
        total_threats_found=2,
    )

    report_path = (
        tmp_path / "report.json"
    )

    assert (
        storage.save_scan(
            result=result,
            report_path=report_path,
        )
        is True
    )

    records = (
        storage
        .read_scan_history()
    )

    assert (
        len(records)
        == 1
    )

    record = records[0]

    assert (
        record["record_type"]
        == "scan"
    )

    assert (
        record["target_name"]
        == "archive.zip"
    )

    assert (
        record["target_sha256"]
        == "archive-sha256"
    )

    assert (
        record["risk_level"]
        == "medium"
    )

    assert (
        record["risk_score"]
        == 45
    )

    assert (
        record["report_path"]
        == str(report_path)
    )


def test_action_history_saves_sha256_and_risk(
    tmp_path: Path,
) -> None:
    storage = (
        create_storage(
            tmp_path
        )
    )

    result = ActionResult(
        success=True,
        action=(
            FileAction.DELETE
        ),
        file_path=(
            tmp_path
            / "danger.exe"
        ),
        message="Файл удалён.",
        sha256=(
            "danger-sha256"
        ),
        risk_score=80,
        risk_level=(
            RiskLevel.CRITICAL
        ),
    )

    assert (
        storage.save_action(
            result
        )
        is True
    )

    record = (
        storage
        .read_action_history()[0]
    )

    assert (
        record["action"]
        == "delete"
    )

    assert (
        record["sha256"]
        == "danger-sha256"
    )

    assert (
        record["risk_level"]
        == "critical"
    )

    assert (
        record["success"]
        is True
    )


def test_action_history_saves_quarantine_result(
    tmp_path: Path,
) -> None:
    storage = (
        create_storage(
            tmp_path
        )
    )

    original_path = (
        tmp_path
        / "danger.zip"
    )

    quarantine_path = (
        tmp_path
        / "quarantine"
        / "danger.quarantine"
    )

    quarantine_result = (
        QuarantineResult(
            success=True,
            provider_name=(
                "Test Quarantine"
            ),
            original_path=(
                original_path
            ),
            quarantine_path=(
                quarantine_path
            ),
            message=(
                "Файл изолирован."
            ),
        )
    )

    result = ActionResult(
        success=True,
        action=(
            FileAction.QUARANTINE
        ),
        file_path=(
            original_path
        ),
        message=(
            "Файл изолирован."
        ),
        sha256=(
            "quarantine-sha256"
        ),
        risk_score=70,
        risk_level=(
            RiskLevel.HIGH
        ),
        quarantine_result=(
            quarantine_result
        ),
    )

    assert (
        storage.save_action(
            result=result,
            quarantine_result=(
                quarantine_result
            ),
        )
        is True
    )

    record = (
        storage
        .read_action_history()[0]
    )

    quarantine_record = (
        record["quarantine"]
    )

    assert (
        quarantine_record[
            "success"
        ]
        is True
    )

    assert (
        quarantine_record[
            "provider_name"
        ]
        == "Test Quarantine"
    )

    assert (
        quarantine_record[
            "quarantine_path"
        ]
        == str(
            quarantine_path
        )
    )


def test_action_history_allows_missing_risk_data(
    tmp_path: Path,
) -> None:
    storage = (
        create_storage(
            tmp_path
        )
    )

    result = ActionResult(
        success=False,
        action=FileAction.KEEP,
        file_path=(
            tmp_path
            / "missing.txt"
        ),
        message=(
            "Файл отсутствует."
        ),
        sha256=None,
        risk_score=None,
        risk_level=None,
    )

    assert (
        storage.save_action(
            result
        )
        is True
    )

    record = (
        storage
        .read_action_history()[0]
    )

    assert (
        record["sha256"]
        is None
    )

    assert (
        record["risk_score"]
        is None
    )

    assert (
        record["risk_level"]
        is None
    )


def test_read_history_skips_corrupted_lines(
    tmp_path: Path,
) -> None:
    scan_history_path = (
        tmp_path
        / "scan_history.jsonl"
    )

    scan_history_path.write_text(
        (
            '{"record_type":"scan",'
            '"target_name":"good.zip"}\n'
            "this is not json\n"
            "[1, 2, 3]\n"
            '{"record_type":"scan",'
            '"target_name":"second.zip"}\n'
        ),
        encoding="utf-8",
    )

    storage = HistoryStorage(
        scan_history_path=(
            scan_history_path
        ),
        action_history_path=(
            tmp_path
            / "action_history.jsonl"
        ),
    )

    records = (
        storage
        .read_scan_history()
    )

    assert [
        record[
            "target_name"
        ]
        for record
        in records
    ] == [
        "good.zip",
        "second.zip",
    ]


def test_read_missing_history_returns_empty_list(
    tmp_path: Path,
) -> None:
    storage = (
        create_storage(
            tmp_path
        )
    )

    assert (
        storage.read_scan_history()
        == []
    )

    assert (
        storage.read_action_history()
        == []
    )


def test_multiple_records_are_appended(
    tmp_path: Path,
) -> None:
    storage = (
        create_storage(
            tmp_path
        )
    )

    for index in range(3):
        result = ActionResult(
            success=True,
            action=FileAction.KEEP,
            file_path=(
                tmp_path
                / f"file_{index}.txt"
            ),
            message="Оставлено.",
        )

        assert (
            storage.save_action(
                result
            )
            is True
        )

    records = (
        storage
        .read_action_history()
    )

    assert (
        len(records)
        == 3
    )