from pathlib import Path

from application.reporting_service import ReportingService
from domain.enums import FileAction
from domain.interfaces import (
    ActionServiceInterface,
    QuarantineProviderInterface,
)
from domain.models import ActionResult
from utils.logger import setup_logger


class ActionService(ActionServiceInterface):
    def __init__(
        self,
        reporting_service: ReportingService,
        quarantine_provider: QuarantineProviderInterface | None = None,
    ) -> None:
        self._quarantine_provider = quarantine_provider
        self._reporting_service = reporting_service
        self._logger = setup_logger()

    def execute(
        self,
        action: FileAction,
        file_path: Path,
    ) -> ActionResult:
        if action == FileAction.KEEP:
            result = self._keep(file_path)

        elif action == FileAction.DELETE:
            result = self._delete(file_path)

        elif action == FileAction.QUARANTINE:
            result = self._quarantine(file_path)

        else:
            result = ActionResult(
                success=False,
                action=action,
                file_path=file_path,
                message="Неизвестное действие.",
            )

        self._reporting_service.save_action_result(
            result=result,
            quarantine_result=result.quarantine_result,
        )

        return result

    def _keep(self, file_path: Path) -> ActionResult:
        if not file_path.exists():
            return ActionResult(
                success=False,
                action=FileAction.KEEP,
                file_path=file_path,
                message="Файл больше не существует.",
            )

        self._logger.info(
            "User kept file: %s",
            file_path,
        )

        return ActionResult(
            success=True,
            action=FileAction.KEEP,
            file_path=file_path,
            message="Файл оставлен в исходной папке.",
        )

    def _delete(self, file_path: Path) -> ActionResult:
        if not file_path.exists():
            return ActionResult(
                success=False,
                action=FileAction.DELETE,
                file_path=file_path,
                message="Файл уже отсутствует.",
            )

        if not file_path.is_file():
            return ActionResult(
                success=False,
                action=FileAction.DELETE,
                file_path=file_path,
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

            return ActionResult(
                success=True,
                action=FileAction.DELETE,
                file_path=file_path,
                message="Файл удалён.",
            )

        except (OSError, PermissionError) as error:
            self._logger.error(
                "Unable to delete file %s: %s",
                file_path,
                error,
            )

            return ActionResult(
                success=False,
                action=FileAction.DELETE,
                file_path=file_path,
                message=(
                    f"Не удалось удалить файл: {error}"
                ),
            )

    def _quarantine(self, file_path: Path) -> ActionResult:
        if self._quarantine_provider is None:
            return ActionResult(
                success=False,
                action=FileAction.QUARANTINE,
                file_path=file_path,
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

        return ActionResult(
            success=quarantine_result.success,
            action=FileAction.QUARANTINE,
            file_path=file_path,
            message=(
                quarantine_result.message
                or (
                    "Файл помещён в карантин."
                    if quarantine_result.success
                    else (
                        "Не удалось поместить "
                        "файл в карантин."
                    )
                )
            ),
            quarantine_result=quarantine_result,
        )