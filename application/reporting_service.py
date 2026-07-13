from pathlib import Path

from domain.models import ActionResult, QuarantineResult, ScanResult
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
        report_path = (
            self._report_writer.write_scan_report(
                result
            )
        )

        history_saved = (
            self._history_storage.save_scan(
                result=result,
                report_path=report_path,
            )
        )

        if not history_saved:
            self._logger.warning(
                "Scan history was not saved for: %s",
                result.target_path,
            )

        return report_path

    def save_action_result(
        self,
        result: ActionResult,
        quarantine_result: QuarantineResult | None = None,
    ) -> bool:
        saved = self._history_storage.save_action(
            result=result,
            quarantine_result=quarantine_result,
        )

        if not saved:
            self._logger.warning(
                "Action history was not saved for: %s",
                result.file_path,
            )

        return saved