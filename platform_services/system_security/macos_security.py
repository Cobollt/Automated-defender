import os
import subprocess
from pathlib import Path

from config import AppConfig
from domain.interfaces import SystemSecurityProviderInterface
from domain.models import SystemSecurityResult
from utils.logger import setup_logger


class MacOSSecurityProvider(SystemSecurityProviderInterface):
    PROVIDER_NAME = "macOS Gatekeeper/XProtect"

    EXECUTABLE_EXTENSIONS = {
        ".app",
        ".command",
        ".dmg",
        ".pkg",
        ".sh",
    }

    def __init__(self) -> None:
        self._logger = setup_logger()

    def report_and_quarantine(
        self,
        file_path: Path,
    ) -> SystemSecurityResult:
        if not file_path.exists():
            return SystemSecurityResult(
                success=False,
                provider_name=self.PROVIDER_NAME,
                file_path=file_path,
                message="Файл не существует.",
            )

        quarantine_marked = self._set_quarantine_attribute(
            file_path
        )

        assessment = self._assess_with_gatekeeper(
            file_path
        )

        details = []

        if quarantine_marked:
            details.append(
                "Файл помечен атрибутом macOS quarantine."
            )
        else:
            details.append(
                "Не удалось установить quarantine-атрибут."
            )

        if assessment is True:
            details.append(
                "Gatekeeper разрешил файл."
            )
        elif assessment is False:
            details.append(
                "Gatekeeper отклонил файл."
            )
        else:
            details.append(
                "Gatekeeper не смог оценить этот тип файла."
            )

        details.append(
            "macOS не предоставила подтверждение "
            "системного перемещения файла."
        )

        return SystemSecurityResult(
            success=quarantine_marked,
            provider_name=self.PROVIDER_NAME,
            file_path=file_path,
            threat_detected=assessment is False,
            file_isolated=False,
            message=" ".join(details),
        )

    def _set_quarantine_attribute(
        self,
        file_path: Path,
    ) -> bool:
        attribute_name = "com.apple.quarantine"

        # Формат содержит флаг, время и имя агента.
        attribute_value = (
            "0081;"
            f"{int(os.path.getmtime(file_path)):x};"
            "AntiArchiveScanner;"
        )

        try:
            os.setxattr(
                file_path,
                attribute_name,
                attribute_value.encode("utf-8"),
            )
            return True

        except (OSError, AttributeError) as error:
            self._logger.warning(
                "Unable to set macOS quarantine attribute "
                "for %s: %s",
                file_path,
                error,
            )
            return False

    def _assess_with_gatekeeper(
        self,
        file_path: Path,
    ) -> bool | None:
        if file_path.suffix.lower() not in self.EXECUTABLE_EXTENSIONS:
            return None

        try:
            process = subprocess.run(
                [
                    "spctl",
                    "--assess",
                    "--type",
                    "execute",
                    "--verbose=4",
                    str(file_path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=AppConfig.SYSTEM_SECURITY_TIMEOUT,
            )

        except (
            OSError,
            subprocess.SubprocessError,
        ) as error:
            self._logger.warning(
                "Unable to assess file with Gatekeeper: %s",
                error,
            )
            return None

        self._logger.info(
            "Gatekeeper assessment code=%s path=%s output=%s",
            process.returncode,
            file_path,
            (
                process.stderr.strip()
                or process.stdout.strip()
            ),
        )

        return process.returncode == 0