from pathlib import Path

from domain.interfaces import (
    QuarantineProviderInterface,
    SystemSecurityProviderInterface,
)
from domain.models import QuarantineResult
from utils.logger import setup_logger


class QuarantineManager(QuarantineProviderInterface):
    PROVIDER_NAME = "Quarantine Manager"

    def __init__(
        self,
        system_provider: SystemSecurityProviderInterface,
        local_provider: QuarantineProviderInterface,
    ) -> None:
        self._system_provider = system_provider
        self._local_provider = local_provider
        self._logger = setup_logger()

    def quarantine(
        self,
        file_path: Path,
    ) -> QuarantineResult:
        if not file_path.exists():
            return QuarantineResult(
                success=False,
                provider_name=self.PROVIDER_NAME,
                original_path=file_path,
                message="Файл не существует.",
            )

        self._logger.warning(
            "Quarantine requested for: %s",
            file_path,
        )

        system_result = (
            self._system_provider.report_and_quarantine(
                file_path
            )
        )

        self._logger.info(
            "System security result: "
            "provider=%s success=%s isolated=%s message=%s",
            system_result.provider_name,
            system_result.success,
            system_result.file_isolated,
            system_result.message,
        )

        if system_result.file_isolated:
            return QuarantineResult(
                success=True,
                provider_name=system_result.provider_name,
                original_path=file_path,
                quarantine_path=None,
                message=(
                    system_result.message
                    or "Файл изолирован системной защитой."
                ),
            )

        if not file_path.exists():
            return QuarantineResult(
                success=True,
                provider_name=system_result.provider_name,
                original_path=file_path,
                quarantine_path=None,
                message=(
                    "После обращения к системной защите "
                    "файл исчез из исходной папки."
                ),
            )

        self._logger.warning(
            "System security did not isolate the file. "
            "Using local quarantine: %s",
            file_path,
        )

        local_result = self._local_provider.quarantine(
            file_path
        )

        if local_result.success:
            system_message = (
                system_result.message
                or "Системная защита не подтвердила действие."
            )

            local_result.message = (
                f"{system_message}\n\n"
                f"{local_result.message}"
            )

        return local_result