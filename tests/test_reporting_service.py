from pathlib import Path

from application.reporting_service import (
    ReportingService,
)
from domain.enums import (
    FileAction,
    RiskLevel,
    ScanStatus,
)
from domain.models import (
    ActionResult,
    ScanResult,
)


class FakeReportWriter:
    def __init__(
        self,
        report_path: (
            Path | None
        ) = None,
        error: (
            Exception | None
        ) = None,
    ) -> None:
        self.report_path = (
            report_path
        )

        self.error = error

        self.results: list[
            ScanResult
        ] = []

    def write_scan_report(
        self,
        result: ScanResult,
    ) -> Path | None:
        self.results.append(
            result
        )

        if self.error is not None:
            raise self.error

        return self.report_path


class FakeHistoryStorage:
    def __init__(
        self,
        scan_saved: bool = True,
        action_saved: bool = True,
        error: (
            Exception | None
        ) = None,
    ) -> None:
        self.scan_saved = (
            scan_saved
        )

        self.action_saved = (
            action_saved
        )

        self.error = error

        self.scans: list[
            tuple[
                ScanResult,
                Path | None,
            ]
        ] = []

        self.actions: list[
            ActionResult
        ] = []

    def save_scan(
        self,
        result: ScanResult,
        report_path: Path | None,
    ) -> bool:
        if self.error is not None:
            raise self.error

        self.scans.append(
            (
                result,
                report_path,
            )
        )

        return self.scan_saved

    def save_action(
        self,
        result: ActionResult,
        quarantine_result=None,
    ) -> bool:
        if self.error is not None:
            raise self.error

        self.actions.append(
            result
        )

        return self.action_saved


def make_scan_result(
    tmp_path: Path,
) -> ScanResult:
    return ScanResult(
        target_path=(
            tmp_path / "file.zip"
        ),
        target_sha256="hash",
        status=(
            ScanStatus.COMPLETED
        ),
        risk_score=70,
        risk_level=(
            RiskLevel.HIGH
        ),
    )


def test_scan_history_is_saved_with_report_path(
    tmp_path: Path,
) -> None:
    report_path = (
        tmp_path / "report.json"
    )

    writer = FakeReportWriter(
        report_path=report_path
    )

    history = (
        FakeHistoryStorage()
    )

    service = ReportingService(
        writer,
        history,
    )

    result = make_scan_result(
        tmp_path
    )

    returned = (
        service.save_scan_result(
            result
        )
    )

    assert (
        returned
        == report_path
    )

    assert (
        history.scans
        == [
            (
                result,
                report_path,
            )
        ]
    )


def test_history_is_still_attempted_when_report_writer_fails(
    tmp_path: Path,
) -> None:
    writer = FakeReportWriter(
        error=OSError(
            "report failed"
        )
    )

    history = (
        FakeHistoryStorage()
    )

    service = ReportingService(
        writer,
        history,
    )

    result = make_scan_result(
        tmp_path
    )

    returned = (
        service.save_scan_result(
            result
        )
    )

    assert returned is None

    assert (
        history.scans
        == [
            (
                result,
                None,
            )
        ]
    )


def test_action_history_failure_returns_false(
    tmp_path: Path,
) -> None:
    writer = (
        FakeReportWriter()
    )

    history = (
        FakeHistoryStorage(
            error=OSError(
                "history failed"
            )
        )
    )

    service = ReportingService(
        writer,
        history,
    )

    action = ActionResult(
        success=True,
        action=(
            FileAction.KEEP
        ),
        file_path=(
            tmp_path
            / "file.zip"
        ),
        message="Оставлено.",
    )

    assert (
        service.save_action_result(
            action
        )
        is False
    )