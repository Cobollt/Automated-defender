from pathlib import Path

from application.reporting_service import ReportingService
from domain.enums import FileAction
from domain.interfaces import (
    ActionServiceInterface,
    QuarantineProviderInterface,
)
from domain.models import (
    ActionResult,
    ScanResult,
)
from utils.logger import setup_logger


class ActionService(ActionServiceInterface):
    def __init__(
        self,
        reporting_service: ReportingService,
        quarantine_provider: QuarantineProviderInterface | None = None,
    ) -> None:
        self._reporting_service = reporting_service
        self._quarantine_provider = quarantine_provider
        self._logger = setup_logger()

    def execute(
        self,
        action: FileAction,
        scan_result: ScanResult,
    ) -> ActionResult:
        file_path = scan_result.target_path

        if action == FileAction.KEEP:
            result = self._keep(
                file_path=file_path,
                scan_result=scan_result,
            )

        elif action == FileAction.DELETE:
            result = self._delete(
                file_path=file_path,
                scan_result=scan_result,
            )

        elif action == FileAction.QUARANTINE:
            result = self._quarantine(
                file_path=file_path,
                scan_result=scan_result,
            )

        else:
            result = self._create_result(
                success=False,
                action=action,
                scan_result=scan_result,
                message="Неизвестное действие.",
            )

        self._reporting_service.save_action_result(
            result=result,
            quarantine_result=result.quarantine_result,
        )

        return result

    def _keep(
        self,
        file_path: Path,
        scan_result: ScanResult,
    ) -> ActionResult:
        if not file_path.exists():
            return self._create_result(
                success=False,
                action=FileAction.KEEP,
                scan_result=scan_result,
                message="Файл больше не существует.",
            )

        self._logger.info(
            "User kept file: %s",
            file_path,
        )

        return self._create_result(
            success=True,
            action=FileAction.KEEP,
            scan_result=scan_result,
            message="Файл оставлен в исходной папке.",
        )

    def _delete(
        self,
        file_path: Path,
        scan_result: ScanResult,
    ) -> ActionResult:
        if not file_path.exists():
            return self._create_result(
                success=False,
                action=FileAction.DELETE,
                scan_result=scan_result,
                message="Файл уже отсутствует.",
            )

        if not file_path.is_file():
            return self._create_result(
                success=False,
                action=FileAction.DELETE,
                scan_result=scan_result,
                message=(
                    "Удалять разрешено только обычные файлы."
                ),
            )

        try:
            file_path.unlink()

            self._logger.warning(
                "User deleted file: %s",
                file_path,
            )

            return self._create_result(
                success=True,
                action=FileAction.DELETE,
                scan_result=scan_result,
                message="Файл удалён.",
            )

        except (OSError, PermissionError) as error:
            self._logger.error(
                "Unable to delete file %s: %s",
                file_path,
                error,
            )

            return self._create_result(
                success=False,
                action=FileAction.DELETE,
                scan_result=scan_result,
                message=(
                    f"Не удалось удалить файл: {error}"
                ),
            )

    def _quarantine(
        self,
        file_path: Path,
        scan_result: ScanResult,
    ) -> ActionResult:
        if self._quarantine_provider is None:
            return self._create_result(
                success=False,
                action=FileAction.QUARANTINE,
                scan_result=scan_result,
                message="Сервис карантина не подключён.",
            )

        quarantine_result = (
            self._quarantine_provider.quarantine(
                file_path
            )
        )

        self._logger.info(
            "Quarantine action for %s: "
            "success=%s, provider=%s",
            file_path,
            quarantine_result.success,
            quarantine_result.provider_name,
        )

        message = (
            quarantine_result.message
            or (
                "Файл помещён в карантин."
                if quarantine_result.success
                else (
                    "Не удалось поместить файл "
                    "в карантин."
                )
            )
        )

        return self._create_result(
            success=quarantine_result.success,
            action=FileAction.QUARANTINE,
            scan_result=scan_result,
            message=message,
            quarantine_result=quarantine_result,
        )

    def _create_result(
        self,
        success: bool,
        action: FileAction,
        scan_result: ScanResult,
        message: str,
        quarantine_result=None,
    ) -> ActionResult:
        return ActionResult(
            success=success,
            action=action,
            file_path=scan_result.target_path,
            message=message,
            sha256=scan_result.target_sha256,
            risk_score=scan_result.risk_score,
            risk_level=scan_result.risk_level,
            quarantine_result=quarantine_result,
        )