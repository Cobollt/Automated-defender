from pathlib import Path

from application.action_service import ActionService
from domain.enums import FileAction, RiskLevel
from domain.models import (
    QuarantineResult,
    ScanResult,
)


class FakeReportingService:
    def __init__(self) -> None:
        self.saved_results = []

    def save_action_result(
        self,
        result,
        quarantine_result=None,
    ) -> bool:
        self.saved_results.append(
            {
                "result": result,
                "quarantine_result": quarantine_result,
            }
        )
        return True


class FakeQuarantineProvider:
    def __init__(self) -> None:
        self.called_with: Path | None = None

    def quarantine(
        self,
        file_path: Path,
    ) -> QuarantineResult:
        self.called_with = file_path

        quarantine_path = (
            file_path.parent
            / f"{file_path.name}.quarantine"
        )

        file_path.rename(quarantine_path)

        return QuarantineResult(
            success=True,
            provider_name="Fake Quarantine",
            original_path=file_path,
            quarantine_path=quarantine_path,
            message="Файл помещён в тестовый карантин.",
        )


def create_scan_result(
    file_path: Path,
) -> ScanResult:
    return ScanResult(
        target_path=file_path,
        target_sha256="test-sha256",
        risk_score=65,
        risk_level=RiskLevel.HIGH,
        total_files_checked=1,
        total_threats_found=2,
    )


def test_keep_preserves_scan_context(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "safe.txt"
    file_path.write_text(
        "safe",
        encoding="utf-8",
    )

    reporting_service = FakeReportingService()

    service = ActionService(
        reporting_service=reporting_service,
    )

    result = service.execute(
        action=FileAction.KEEP,
        scan_result=create_scan_result(file_path),
    )

    assert result.success is True
    assert file_path.exists()

    assert result.action == FileAction.KEEP
    assert result.file_path == file_path
    assert result.sha256 == "test-sha256"
    assert result.risk_score == 65
    assert result.risk_level == RiskLevel.HIGH

    assert len(reporting_service.saved_results) == 1

    saved_result = reporting_service.saved_results[0]["result"]

    assert saved_result is result


def test_delete_removes_file_and_preserves_scan_context(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.txt"
    file_path.write_text(
        "danger",
        encoding="utf-8",
    )

    reporting_service = FakeReportingService()

    service = ActionService(
        reporting_service=reporting_service,
    )

    result = service.execute(
        action=FileAction.DELETE,
        scan_result=create_scan_result(file_path),
    )

    assert result.success is True
    assert not file_path.exists()

    assert result.action == FileAction.DELETE
    assert result.sha256 == "test-sha256"
    assert result.risk_score == 65
    assert result.risk_level == RiskLevel.HIGH

    assert len(reporting_service.saved_results) == 1


def test_delete_missing_file_returns_failure(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "missing.txt"

    reporting_service = FakeReportingService()

    service = ActionService(
        reporting_service=reporting_service,
    )

    result = service.execute(
        action=FileAction.DELETE,
        scan_result=create_scan_result(file_path),
    )

    assert result.success is False
    assert result.action == FileAction.DELETE

    assert result.sha256 == "test-sha256"
    assert result.risk_score == 65
    assert result.risk_level == RiskLevel.HIGH

    assert len(reporting_service.saved_results) == 1


def test_quarantine_uses_provider_and_preserves_context(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.exe"
    file_path.write_bytes(b"MZ test")

    reporting_service = FakeReportingService()
    quarantine_provider = FakeQuarantineProvider()

    service = ActionService(
        reporting_service=reporting_service,
        quarantine_provider=quarantine_provider,
    )

    result = service.execute(
        action=FileAction.QUARANTINE,
        scan_result=create_scan_result(file_path),
    )

    assert result.success is True
    assert quarantine_provider.called_with == file_path

    assert not file_path.exists()
    assert result.quarantine_result is not None
    assert result.quarantine_result.quarantine_path is not None
    assert result.quarantine_result.quarantine_path.exists()

    assert result.sha256 == "test-sha256"
    assert result.risk_score == 65
    assert result.risk_level == RiskLevel.HIGH

    assert len(reporting_service.saved_results) == 1

    saved_entry = reporting_service.saved_results[0]

    assert (
        saved_entry["quarantine_result"]
        is result.quarantine_result
    )


def test_quarantine_without_provider_returns_failure(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.exe"
    file_path.write_bytes(b"MZ test")

    reporting_service = FakeReportingService()

    service = ActionService(
        reporting_service=reporting_service,
        quarantine_provider=None,
    )

    result = service.execute(
        action=FileAction.QUARANTINE,
        scan_result=create_scan_result(file_path),
    )

    assert result.success is False
    assert file_path.exists()

    assert result.sha256 == "test-sha256"
    assert result.risk_score == 65
    assert result.risk_level == RiskLevel.HIGH

    assert len(reporting_service.saved_results) == 1