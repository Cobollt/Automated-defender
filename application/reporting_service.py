from pathlib import Path

from domain.models import (
    ActionResult,
    QuarantineResult,
    ScanResult,
)
from infrastructure.history_storage import HistoryStorage
from infrastructure.report_writer import ReportWriter
from utils.logger import setup_logger


class ReportingService:
    def __init__(
        self,
        report_writer: ReportWriter,
        history_storage: HistoryStorage,
    ) -> None:
        self._report_writer = report_writer
        self._history_storage = history_storage
        self._logger = setup_logger()

    def save_scan_result(
        self,
        result: ScanResult,
    ) -> Path | None:
        report_path: Path | None = None

        try:
            report_path = (
                self._report_writer
                .write_scan_report(
                    result
                )
            )

        except Exception:
            self._logger.exception(
                "Unexpected error while "
                "writing scan report for: %s",
                result.target_path,
            )

        try:
            history_saved = (
                self._history_storage
                .save_scan(
                    result=result,
                    report_path=(
                        report_path
                    ),
                )
            )

        except Exception:
            self._logger.exception(
                "Unexpected error while "
                "writing scan history for: %s",
                result.target_path,
            )

            history_saved = False

        if report_path is None:
            self._logger.warning(
                "Scan report was not "
                "created for: %s",
                result.target_path,
            )

        else:
            self._logger.info(
                "Scan report saved "
                "for %s: %s",
                result.target_path,
                report_path,
            )

        if not history_saved:
            self._logger.warning(
                "Scan history was not "
                "saved for: %s",
                result.target_path,
            )

        return report_path

    def save_action_result(
        self,
        result: ActionResult,
        quarantine_result: (
            QuarantineResult | None
        ) = None,
    ) -> bool:
        effective_quarantine_result = (
            quarantine_result
            or result.quarantine_result
        )

        try:
            saved = (
                self._history_storage
                .save_action(
                    result=result,
                    quarantine_result=(
                        effective_quarantine_result
                    ),
                )
            )

        except Exception:
            self._logger.exception(
                "Unexpected error while "
                "writing action history: "
                "action=%s file=%s",
                result.action.value,
                result.file_path,
            )

            return False

        if saved:
            self._logger.info(
                "Action history saved: "
                "action=%s file=%s success=%s",
                result.action.value,
                result.file_path,
                result.success,
            )

        else:
            self._logger.warning(
                "Action history was not "
                "saved: action=%s file=%s",
                result.action.value,
                result.file_path,
            )

        return saved