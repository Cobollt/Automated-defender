import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from config import AppConfig
from domain.models import DetectedThreat, ScanResult
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
        generated_at = datetime.now(timezone.utc)

        base_name = (
            f"{AppConfig.REPORT_FILE_PREFIX}_"
            f"{generated_at.strftime('%Y%m%d_%H%M%S')}_"
            f"{report_id[:8]}"
        )

        json_path = self._reports_dir / f"{base_name}.json"
        text_path = self._reports_dir / f"{base_name}.txt"

        report_data = self._build_scan_report(
            report_id=report_id,
            result=result,
            generated_at=generated_at,
        )

        json_written = self._write_json_report(
            report_path=json_path,
            report_data=report_data,
        )

        text_written = self._write_text_report(
            report_path=text_path,
            result=result,
            report_id=report_id,
            generated_at=generated_at,
        )

        if not json_written and not text_written:
            return None

        self._cleanup_old_reports()

        if json_written:
            return json_path

        return text_path

    def _write_json_report(
        self,
        report_path: Path,
        report_data: dict,
    ) -> bool:
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
                "JSON scan report written: %s",
                report_path,
            )

            return True

        except (OSError, TypeError, ValueError) as error:
            self._logger.exception(
                "Unable to write JSON report %s: %s",
                report_path,
                error,
            )

            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass

            return False

    def _write_text_report(
        self,
        report_path: Path,
        result: ScanResult,
        report_id: str,
        generated_at: datetime,
    ) -> bool:
        temporary_path = report_path.with_suffix(".tmp")

        lines = [
            "AntiArchiveScanner — отчёт проверки",
            "=" * 60,
            f"Report ID: {report_id}",
            f"Дата формирования: {generated_at.isoformat()}",
            "",
            "Проверяемый объект",
            "-" * 60,
            f"Имя: {result.target_path.name}",
            f"Путь: {result.target_path}",
            f"SHA-256: {result.target_sha256 or 'не вычислен'}",
            "",
            "Результат проверки",
            "-" * 60,
            f"Статус: {result.status.value}",
            f"Уровень риска: {result.risk_level.value}",
            f"Оценка риска: {result.risk_score}/100",
            f"Проверено файлов: {result.total_files_checked}",
            f"Найдено признаков: {result.total_threats_found}",
            f"Начало проверки: {result.started_at.isoformat()}",
            (
                "Завершение проверки: "
                f"{result.finished_at.isoformat()}"
                if result.finished_at
                else "Завершение проверки: не завершена"
            ),
            (
                f"Ошибка: {result.error_message}"
                if result.error_message
                else "Ошибка: отсутствует"
            ),
            "",
            "Угрозы архива",
            "-" * 60,
        ]

        if result.archive_threats:
            for index, threat in enumerate(
                result.archive_threats,
                start=1,
            ):
                lines.extend(
                    self._format_text_threat(
                        index=index,
                        threat=threat,
                    )
                )
        else:
            lines.append("Угрозы архива не обнаружены.")

        lines.extend(
            [
                "",
                "Проверенные файлы",
                "-" * 60,
            ]
        )

        if not result.file_results:
            lines.append("Файлы не проверялись.")
        else:
            for index, file_result in enumerate(
                result.file_results,
                start=1,
            ):
                displayed_path = (
                    file_result.relative_path
                    or file_result.file_path.name
                )

                lines.extend(
                    [
                        "",
                        f"{index}. {displayed_path}",
                        f"   SHA-256: {file_result.sha256}",
                        (
                            "   Уровень риска: "
                            f"{file_result.risk_level.value}"
                        ),
                        (
                            "   Оценка риска: "
                            f"{file_result.risk_score}/100"
                        ),
                        (
                            "   Найдено признаков: "
                            f"{len(file_result.threats)}"
                        ),
                    ]
                )

                if file_result.threats:
                    for threat_index, threat in enumerate(
                        file_result.threats,
                        start=1,
                    ):
                        lines.extend(
                            self._format_text_threat(
                                index=threat_index,
                                threat=threat,
                                indentation="      ",
                            )
                        )
                else:
                    lines.append(
                        "   Подозрительные признаки не обнаружены."
                    )

        try:
            temporary_path.write_text(
                "\n".join(lines) + "\n",
                encoding="utf-8",
            )

            temporary_path.replace(report_path)

            self._logger.info(
                "Text scan report written: %s",
                report_path,
            )

            return True

        except OSError as error:
            self._logger.exception(
                "Unable to write text report %s: %s",
                report_path,
                error,
            )

            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass

            return False

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
                "sha256": result.target_sha256,
            },
            "scan": {
                "status": result.status.value,
                "started_at": result.started_at.isoformat(),
                "finished_at": (
                    result.finished_at.isoformat()
                    if result.finished_at
                    else None
                ),
                "total_files_checked": (
                    result.total_files_checked
                ),
                "total_threats_found": (
                    result.total_threats_found
                ),
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
                    "path": (
                        file_result.relative_path
                        or file_result.file_path.name
                    ),
                    "sha256": file_result.sha256,
                    "risk_score": file_result.risk_score,
                    "risk_level": (
                        file_result.risk_level.value
                    ),
                    "threats": [
                        self._serialize_threat(threat)
                        for threat in file_result.threats
                    ],
                }
                for file_result in result.file_results
            ],
        }

    def _serialize_threat(
        self,
        threat: DetectedThreat,
    ) -> dict:
        return {
            "type": threat.threat_type.value,
            "description": threat.description,
            "score": threat.score,
            "path": (
                threat.relative_path
                or (
                    threat.file_path.name
                    if threat.file_path
                    else None
                )
            ),
        }

    def _format_text_threat(
        self,
        index: int,
        threat: DetectedThreat,
        indentation: str = "",
    ) -> list[str]:
        displayed_path = (
            threat.relative_path
            or (
                threat.file_path.name
                if threat.file_path
                else "не указан"
            )
        )

        return [
            (
                f"{indentation}{index}. "
                f"{threat.threat_type.value}"
            ),
            (
                f"{indentation}   Описание: "
                f"{threat.description}"
            ),
            (
                f"{indentation}   Оценка: "
                f"{threat.score}"
            ),
            (
                f"{indentation}   Путь: "
                f"{displayed_path}"
            ),
        ]

    def _cleanup_old_reports(self) -> None:
        report_files = []

        report_files.extend(
            self._reports_dir.glob(
                f"{AppConfig.REPORT_FILE_PREFIX}_*.json"
            )
        )

        report_files.extend(
            self._reports_dir.glob(
                f"{AppConfig.REPORT_FILE_PREFIX}_*.txt"
            )
        )

        report_files = sorted(
            report_files,
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

        maximum_files = AppConfig.MAX_REPORT_FILES * 2

        old_reports = report_files[maximum_files:]

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