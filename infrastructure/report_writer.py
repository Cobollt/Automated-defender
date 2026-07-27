import json
import os
from datetime import (
    datetime,
    timezone,
)
from pathlib import Path
from uuid import uuid4

from config import AppConfig
from domain.models import (
    DetectedThreat,
    ScanResult,
)
from utils.logger import setup_logger


class ReportWriter:
    def __init__(
        self,
        reports_dir: Path | None = None,
    ) -> None:
        self._reports_dir = (
            reports_dir
            or AppConfig.REPORTS_DIR
        )

        self._logger = setup_logger()

    def write_scan_report(
        self,
        result: ScanResult,
    ) -> Path | None:
        try:
            self._reports_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

        except OSError as error:
            self._logger.exception(
                "Unable to create reports "
                "directory %s: %s",
                self._reports_dir,
                error,
            )

            return None

        report_id = uuid4().hex

        generated_at = (
            datetime.now(
                timezone.utc
            )
        )

        base_name = (
            f"{AppConfig.REPORT_FILE_PREFIX}_"
            f"{generated_at.strftime('%Y%m%d_%H%M%S_%f')}_"
            f"{report_id[:8]}"
        )

        json_path = (
            self._reports_dir
            / f"{base_name}.json"
        )

        text_path = (
            self._reports_dir
            / f"{base_name}.txt"
        )

        report_data = (
            self._build_scan_report(
                report_id=report_id,
                result=result,
                generated_at=generated_at,
            )
        )

        json_written = (
            self._write_json_report(
                json_path,
                report_data,
            )
        )

        text_written = (
            self._write_text_report(
                report_path=text_path,
                result=result,
                report_id=report_id,
                generated_at=generated_at,
            )
        )

        if (
            not json_written
            and not text_written
        ):
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
        try:
            payload = (
                json.dumps(
                    report_data,
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n"
            )

        except (
            TypeError,
            ValueError,
        ) as error:
            self._logger.exception(
                "Unable to serialize "
                "JSON report %s: %s",
                report_path,
                error,
            )

            return False

        return self._write_text_atomically(
            report_path=report_path,
            content=payload,
            report_type="JSON",
        )

    def _write_text_report(
        self,
        report_path: Path,
        result: ScanResult,
        report_id: str,
        generated_at: datetime,
    ) -> bool:
        lines = [
            (
                "AntiArchiveScanner — "
                "отчёт проверки"
            ),
            "=" * 60,
            f"Report ID: {report_id}",
            (
                "Дата формирования: "
                f"{generated_at.isoformat()}"
            ),
            "",
            "Проверяемый объект",
            "-" * 60,
            (
                f"Имя: "
                f"{result.target_path.name}"
            ),
            (
                f"Путь: "
                f"{result.target_path.name}"
            ),
            (
                "SHA-256: "
                f"{result.target_sha256 or 'не вычислен'}"
            ),
            "",
            "Результат проверки",
            "-" * 60,
            (
                f"Статус: "
                f"{result.status.value}"
            ),
            (
                f"Уровень риска: "
                f"{result.risk_level.value}"
            ),
            (
                f"Оценка риска: "
                f"{result.risk_score}/100"
            ),
            (
                "Проверено файлов: "
                f"{result.total_files_checked}"
            ),
            (
                "Найдено признаков: "
                f"{result.total_threats_found}"
            ),
            (
                "Начало проверки: "
                f"{result.started_at.isoformat()}"
            ),
            (
                "Завершение проверки: "
                f"{result.finished_at.isoformat()}"
                if result.finished_at
                else (
                    "Завершение проверки: "
                    "не завершена"
                )
            ),
            (
                f"Ошибка: "
                f"{result.error_message}"
                if result.error_message
                else (
                    "Ошибка: отсутствует"
                )
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
            lines.append(
                "Угрозы архива "
                "не обнаружены."
            )

        lines.extend(
            [
                "",
                "Проверенные файлы",
                "-" * 60,
            ]
        )

        if not result.file_results:
            lines.append(
                "Файлы не проверялись."
            )

        else:
            for index, file_result in (
                enumerate(
                    result.file_results,
                    start=1,
                )
            ):
                displayed_path = (
                    file_result.relative_path
                    or file_result
                    .file_path
                    .name
                )

                lines.extend(
                    [
                        "",
                        (
                            f"{index}. "
                            f"{displayed_path}"
                        ),
                        (
                            "   SHA-256: "
                            f"{file_result.sha256}"
                        ),
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
                    for (
                        threat_index,
                        threat,
                    ) in enumerate(
                        file_result.threats,
                        start=1,
                    ):
                        lines.extend(
                            self._format_text_threat(
                                index=(
                                    threat_index
                                ),
                                threat=threat,
                                indentation="      ",
                            )
                        )

                else:
                    lines.append(
                        "   Подозрительные "
                        "признаки "
                        "не обнаружены."
                    )

        return self._write_text_atomically(
            report_path=report_path,
            content=(
                "\n".join(lines)
                + "\n"
            ),
            report_type="Text",
        )

    def _write_text_atomically(
        self,
        report_path: Path,
        content: str,
        report_type: str,
    ) -> bool:
        temporary_path = (
            report_path.with_name(
                report_path.name
                + ".tmp"
            )
        )

        try:
            with temporary_path.open(
                "x",
                encoding="utf-8",
                newline="\n",
            ) as target:
                target.write(
                    content
                )

                target.flush()

                os.fsync(
                    target.fileno()
                )

            temporary_path.replace(
                report_path
            )

            self._logger.info(
                "%s scan report "
                "written: %s",
                report_type,
                report_path,
            )

            return True

        except OSError as error:
            self._logger.exception(
                "Unable to write "
                "%s report %s: %s",
                report_type,
                report_path,
                error,
            )

            try:
                temporary_path.unlink(
                    missing_ok=True
                )

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
            "generated_at": (
                generated_at
                .isoformat()
            ),
            "target": {
                "name": (
                    result
                    .target_path
                    .name
                ),
                "path": (
                    result
                    .target_path
                    .name
                ),
                "sha256": (
                    result
                    .target_sha256
                ),
            },
            "scan": {
                "status": (
                    result.status.value
                ),
                "started_at": (
                    result
                    .started_at
                    .isoformat()
                ),
                "finished_at": (
                    result
                    .finished_at
                    .isoformat()
                    if (
                        result
                        .finished_at
                    )
                    else None
                ),
                "total_files_checked": (
                    result
                    .total_files_checked
                ),
                "total_threats_found": (
                    result
                    .total_threats_found
                ),
                "risk_score": (
                    result.risk_score
                ),
                "risk_level": (
                    result
                    .risk_level
                    .value
                ),
                "error_message": (
                    result
                    .error_message
                ),
            },
            "archive_threats": [
                self._serialize_threat(
                    threat
                )
                for threat
                in result.archive_threats
            ],
            "file_results": [
                {
                    "path": (
                        file_result
                        .relative_path
                        or file_result
                        .file_path
                        .name
                    ),
                    "sha256": (
                        file_result
                        .sha256
                    ),
                    "risk_score": (
                        file_result
                        .risk_score
                    ),
                    "risk_level": (
                        file_result
                        .risk_level
                        .value
                    ),
                    "threats": [
                        self._serialize_threat(
                            threat
                        )
                        for threat
                        in file_result.threats
                    ],
                }
                for file_result
                in result.file_results
            ],
        }

    @staticmethod
    def _serialize_threat(
        threat: DetectedThreat,
    ) -> dict:
        return {
            "type": (
                threat
                .threat_type
                .value
            ),
            "description": (
                threat.description
            ),
            "score": (
                threat.score
            ),
            "path": (
                threat.relative_path
                or (
                    threat
                    .file_path
                    .name
                    if threat.file_path
                    else None
                )
            ),
        }

    @staticmethod
    def _format_text_threat(
        index: int,
        threat: DetectedThreat,
        indentation: str = "",
    ) -> list[str]:
        displayed_path = (
            threat.relative_path
            or (
                threat
                .file_path
                .name
                if threat.file_path
                else "не указан"
            )
        )

        return [
            (
                f"{indentation}"
                f"{index}. "
                f"{threat.threat_type.value}"
            ),
            (
                f"{indentation}"
                "   Описание: "
                f"{threat.description}"
            ),
            (
                f"{indentation}"
                "   Оценка: "
                f"{threat.score}"
            ),
            (
                f"{indentation}"
                "   Путь: "
                f"{displayed_path}"
            ),
        ]

    def _cleanup_old_reports(
        self,
    ) -> None:
        try:
            json_reports = list(
                self._reports_dir.glob(
                    (
                        f"{AppConfig.REPORT_FILE_PREFIX}"
                        "_*.json"
                    )
                )
            )

        except OSError as error:
            self._logger.warning(
                "Unable to list reports "
                "for cleanup: %s",
                error,
            )

            return

        def safe_mtime(
            path: Path,
        ) -> float:
            try:
                return (
                    path.stat().st_mtime
                )

            except OSError:
                return 0.0

        json_reports.sort(
            key=safe_mtime,
            reverse=True,
        )

        old_json_reports = (
            json_reports[
                AppConfig
                .MAX_REPORT_FILES:
            ]
        )

        for json_path in (
            old_json_reports
        ):
            text_path = (
                json_path.with_suffix(
                    ".txt"
                )
            )

            for report_path in (
                json_path,
                text_path,
            ):
                try:
                    report_path.unlink(
                        missing_ok=True
                    )

                    self._logger.info(
                        "Old report "
                        "removed: %s",
                        report_path,
                    )

                except OSError as error:
                    self._logger.warning(
                        "Unable to remove "
                        "old report %s: %s",
                        report_path,
                        error,
                    )