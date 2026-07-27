from pathlib import Path

from domain.interfaces import (
    QuarantineProviderInterface,
    SystemSecurityProviderInterface,
)
from domain.models import (
    QuarantineResult,
    SystemSecurityResult,
)
from utils.logger import setup_logger


class QuarantineManager(
    QuarantineProviderInterface
):
    PROVIDER_NAME = (
        "Quarantine Manager"
    )

    def __init__(
        self,
        system_provider: (
            SystemSecurityProviderInterface
        ),
        local_provider: (
            QuarantineProviderInterface
        ),
    ) -> None:
        self._system_provider = (
            system_provider
        )

        self._local_provider = (
            local_provider
        )

        self._logger = setup_logger()

    def quarantine(
        self,
        file_path: Path,
    ) -> QuarantineResult:
        file_path = Path(
            file_path
        )

        if not file_path.exists():
            return self._failure(
                file_path=file_path,
                message=(
                    "Файл не существует."
                ),
            )

        if file_path.is_symlink():
            return self._failure(
                file_path=file_path,
                message=(
                    "Символические ссылки "
                    "нельзя помещать "
                    "в карантин."
                ),
            )

        if not file_path.is_file():
            return self._failure(
                file_path=file_path,
                message=(
                    "В карантин можно "
                    "перемещать только "
                    "обычные файлы."
                ),
            )

        self._logger.warning(
            "Quarantine requested for: %s",
            file_path,
        )

        system_result = (
            self._try_system_quarantine(
                file_path
            )
        )

        if (
            system_result.file_isolated
        ):
            self._logger.warning(
                "File isolated by system "
                "security provider: %s",
                file_path,
            )

            return QuarantineResult(
                success=True,
                provider_name=(
                    system_result
                    .provider_name
                ),
                original_path=file_path,
                quarantine_path=None,
                message=(
                    system_result.message
                    or (
                        "Файл изолирован "
                        "системной защитой."
                    )
                ),
            )

        if not file_path.exists():
            self._logger.warning(
                "File disappeared after "
                "system security request: %s",
                file_path,
            )

            return QuarantineResult(
                success=True,
                provider_name=(
                    system_result
                    .provider_name
                ),
                original_path=file_path,
                quarantine_path=None,
                message=(
                    "После обращения к "
                    "системной защите файл "
                    "исчез из исходной папки."
                ),
            )

        if file_path.is_symlink():
            return self._failure(
                file_path=file_path,
                message=(
                    "После обращения к "
                    "системной защите путь "
                    "стал символической "
                    "ссылкой."
                ),
            )

        if not file_path.is_file():
            return self._failure(
                file_path=file_path,
                message=(
                    "После обращения к "
                    "системной защите путь "
                    "больше не является "
                    "обычным файлом."
                ),
            )

        self._logger.warning(
            "System security did not "
            "isolate file. "
            "Using local quarantine: %s",
            file_path,
        )

        local_result = (
            self._try_local_quarantine(
                file_path
            )
        )

        if local_result.success:
            local_result.message = (
                self._combine_messages(
                    system_result.message,
                    local_result.message,
                )
            )

        return local_result

    def _try_system_quarantine(
        self,
        file_path: Path,
    ) -> SystemSecurityResult:
        try:
            result = (
                self
                ._system_provider
                .report_and_quarantine(
                    file_path
                )
            )

        except Exception as error:
            self._logger.exception(
                "System security provider "
                "failed for %s",
                file_path,
            )

            return SystemSecurityResult(
                success=False,
                provider_name=(
                    self.PROVIDER_NAME
                ),
                file_path=file_path,
                threat_detected=False,
                file_isolated=False,
                message=(
                    "Системная защита "
                    "завершилась ошибкой: "
                    f"{error}"
                ),
            )

        self._logger.info(
            "System security result: "
            "provider=%s "
            "success=%s "
            "isolated=%s "
            "message=%s",
            result.provider_name,
            result.success,
            result.file_isolated,
            result.message,
        )

        return result

    def _try_local_quarantine(
        self,
        file_path: Path,
    ) -> QuarantineResult:
        try:
            return (
                self._local_provider
                .quarantine(
                    file_path
                )
            )

        except Exception as error:
            self._logger.exception(
                "Local quarantine provider "
                "failed for %s",
                file_path,
            )

            return QuarantineResult(
                success=False,
                provider_name=(
                    self.PROVIDER_NAME
                ),
                original_path=file_path,
                quarantine_path=None,
                message=(
                    "Не удалось переместить "
                    "файл в локальный "
                    "карантин: "
                    f"{error}"
                ),
            )

    def _failure(
        self,
        file_path: Path,
        message: str,
    ) -> QuarantineResult:
        return QuarantineResult(
            success=False,
            provider_name=(
                self.PROVIDER_NAME
            ),
            original_path=file_path,
            quarantine_path=None,
            message=message,
        )

    @staticmethod
    def _combine_messages(
        system_message: str | None,
        local_message: str | None,
    ) -> str:
        system_text = (
            system_message
            or (
                "Системная защита "
                "не подтвердила "
                "изоляцию файла."
            )
        )

        local_text = (
            local_message
            or (
                "Файл перемещён "
                "в локальный карантин."
            )
        )

        return (
            f"{system_text}\n\n"
            f"{local_text}"
        )