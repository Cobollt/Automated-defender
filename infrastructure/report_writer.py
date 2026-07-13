import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from config import AppConfig
from domain.models import ScanResult
from utils.logger import setup_logger


class ReportWriter:
    def __init__(
        self,
        reports_dir: Path | None = None,
    ) -> None:
        self._reports_dir = (
            reports_dir or AppConfig.REPORTS_DIR
        )
        self._logger = setup_logger()

    def write_scan_report(
        self,
        result: ScanResult,
    ) -> Path | None:
        self._reports_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        report_id = uuid4().hex
        timestamp = datetime.now(timezone.utc)

        file_name = (
            f"{AppConfig.REPORT_FILE_PREFIX}_"
            f"{timestamp.strftime('%Y%m%d_%H%M%S')}_"
            f"{report_id[:8]}.json"
        )

        report_path = self._reports_dir / file_name

        report_data = self._build_scan_report(
            report_id=report_id,
            result=result,
            generated_at=timestamp,
        )

        temporary_path = report_path.with_suffix(".tmp")

        try:
            temporary_path.write_text(
                json.dumps(
                    report_data,
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            temporary_path.replace(report_path)

            self._logger.info(
                "Scan report written: %s",
                report_path,
            )

            self._cleanup_old_reports()

            return report_path

        except (OSError, TypeError, ValueError) as error:
            self._logger.exception(
                "Unable to write scan report for %s: %s",
                result.target_path,
                error,
            )

            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass

            return None

    def _build_scan_report(
        self,
        report_id: str,
        result: ScanResult,
        generated_at: datetime,
    ) -> dict:
        return {
            "report_id": report_id,
            "generated_at": generated_at.isoformat(),
            "target": {
                "name": result.target_path.name,
                "path": str(result.target_path),
            },
            "scan": {
                "status": result.status.value,
                "started_at": result.started_at.isoformat(),
                "finished_at": (
                    result.finished_at.isoformat()
                    if result.finished_at
                    else None
                ),
                "total_files_checked": result.total_files_checked,
                "total_threats_found": result.total_threats_found,
                "risk_score": result.risk_score,
                "risk_level": result.risk_level.value,
                "error_message": result.error_message,
            },
            "archive_threats": [
                self._serialize_threat(threat)
                for threat in result.archive_threats
            ],
            "file_results": [
                {
                    "file_path": str(file_result.file_path),
                    "sha256": file_result.sha256,
                    "risk_score": file_result.risk_score,
                    "risk_level": file_result.risk_level.value,
                    "threats": [
                        self._serialize_threat(threat)
                        for threat in file_result.threats
                    ],
                }
                for file_result in result.file_results
            ],
        }

    def _serialize_threat(self, threat) -> dict:
        return {
            "type": threat.threat_type.value,
            "description": threat.description,
            "score": threat.score,
            "file_path": (
                str(threat.file_path)
                if threat.file_path
                else None
            ),
        }

    def _cleanup_old_reports(self) -> None:
        report_files = sorted(
            self._reports_dir.glob(
                f"{AppConfig.REPORT_FILE_PREFIX}_*.json"
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

        old_reports = report_files[
            AppConfig.MAX_REPORT_FILES:
        ]

        for report_path in old_reports:
            try:
                report_path.unlink()

                self._logger.info(
                    "Old report removed: %s",
                    report_path,
                )

            except OSError as error:
                self._logger.warning(
                    "Unable to remove old report %s: %s",
                    report_path,
                    error,
                )