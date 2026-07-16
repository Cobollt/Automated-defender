import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import AppConfig
from domain.models import (
    ActionResult,
    QuarantineResult,
    ScanResult,
)
from utils.logger import setup_logger


class HistoryStorage:
    def __init__(
        self,
        scan_history_path: Path | None = None,
        action_history_path: Path | None = None,
    ) -> None:
        self._scan_history_path = (
            scan_history_path
            or AppConfig.REPORT_HISTORY_FILE
        )

        self._action_history_path = (
            action_history_path
            or AppConfig.ACTION_HISTORY_FILE
        )

        self._write_lock = threading.Lock()
        self._logger = setup_logger()

    def save_scan(
        self,
        result: ScanResult,
        report_path: Path | None,
    ) -> bool:
        record = {
            "record_type": "scan",
            "recorded_at": self._utc_now(),
            "target_name": result.target_path.name,
            "target_path": str(result.target_path),
            "target_sha256": result.target_sha256,
            "status": result.status.value,
            "risk_level": result.risk_level.value,
            "risk_score": result.risk_score,
            "total_files_checked": result.total_files_checked,
            "total_threats_found": result.total_threats_found,
            "started_at": result.started_at.isoformat(),
            "finished_at": (
                result.finished_at.isoformat()
                if result.finished_at
                else None
            ),
            "error_message": result.error_message,
            "report_path": (
                str(report_path)
                if report_path
                else None
            ),
        }

        return self._append_record(
            path=self._scan_history_path,
            record=record,
        )

    def save_action(
        self,
        result: ActionResult,
        quarantine_result: QuarantineResult | None = None,
    ) -> bool:
        record: dict[str, Any] = {
            "record_type": "action",
            "recorded_at": self._utc_now(),
            "file_name": result.file_path.name,
            "file_path": str(result.file_path),
            "sha256": result.sha256,
            "risk_score": result.risk_score,
            "risk_level": (
                result.risk_level.value
                if result.risk_level is not None
                else None
            ),
            "action": result.action.value,
            "success": result.success,
            "message": result.message,
        }

        effective_quarantine_result = (
            quarantine_result
            or result.quarantine_result
        )

        if effective_quarantine_result is not None:
            record["quarantine"] = {
                "success": effective_quarantine_result.success,
                "provider_name": (
                    effective_quarantine_result.provider_name
                ),
                "original_path": str(
                    effective_quarantine_result.original_path
                ),
                "quarantine_path": (
                    str(
                        effective_quarantine_result.quarantine_path
                    )
                    if effective_quarantine_result.quarantine_path
                    else None
                ),
                "message": (
                    effective_quarantine_result.message
                ),
            }

        return self._append_record(
            path=self._action_history_path,
            record=record,
        )

    def _append_record(
        self,
        path: Path,
        record: dict[str, Any],
    ) -> bool:
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        serialized_record = json.dumps(
            record,
            ensure_ascii=False,
        )

        try:
            with self._write_lock:
                with path.open(
                    "a",
                    encoding="utf-8",
                ) as history_file:
                    history_file.write(
                        serialized_record + "\n"
                    )
                    history_file.flush()

            self._logger.info(
                "History record saved: %s",
                path,
            )

            return True

        except OSError as error:
            self._logger.exception(
                "Unable to write history record to %s: %s",
                path,
                error,
            )

            return False

    def _utc_now(self) -> str:
        return datetime.now(
            timezone.utc
        ).isoformat()