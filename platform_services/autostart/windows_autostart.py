import subprocess

from config import AppConfig
from domain.interfaces import AutostartServiceInterface
from platform_services.autostart.command_builder import (
    ApplicationCommandBuilder,
)
from utils.logger import setup_logger


class WindowsAutostartService(AutostartServiceInterface):
    def __init__(self) -> None:
        self._logger = setup_logger()

    def enable(self) -> bool:
        command = (
            ApplicationCommandBuilder.build_windows_command()
        )

        try:
            result = subprocess.run(
                [
                    "schtasks.exe",
                    "/Create",
                    "/TN",
                    AppConfig.AUTOSTART_TASK_NAME,
                    "/TR",
                    command,
                    "/SC",
                    "ONLOGON",
                    "/F",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
                creationflags=self._creation_flags(),
            )

            if result.returncode != 0:
                self._logger.error(
                    "Unable to enable Windows autostart: %s",
                    result.stderr.strip()
                    or result.stdout.strip(),
                )
                return False

            self._logger.info(
                "Windows autostart enabled"
            )

            return True

        except (
            OSError,
            subprocess.SubprocessError,
        ) as error:
            self._logger.exception(
                "Unable to enable Windows autostart: %s",
                error,
            )
            return False

    def disable(self) -> bool:
        try:
            result = subprocess.run(
                [
                    "schtasks.exe",
                    "/Delete",
                    "/TN",
                    AppConfig.AUTOSTART_TASK_NAME,
                    "/F",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
                creationflags=self._creation_flags(),
            )

            if result.returncode != 0:
                output = (
                    result.stderr.strip()
                    or result.stdout.strip()
                )

                if not self.is_enabled():
                    return True

                self._logger.error(
                    "Unable to disable Windows autostart: %s",
                    output,
                )
                return False

            self._logger.info(
                "Windows autostart disabled"
            )

            return True

        except (
            OSError,
            subprocess.SubprocessError,
        ) as error:
            self._logger.exception(
                "Unable to disable Windows autostart: %s",
                error,
            )
            return False

    def is_enabled(self) -> bool:
        try:
            result = subprocess.run(
                [
                    "schtasks.exe",
                    "/Query",
                    "/TN",
                    AppConfig.AUTOSTART_TASK_NAME,
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
                creationflags=self._creation_flags(),
            )

            return result.returncode == 0

        except (
            OSError,
            subprocess.SubprocessError,
        ):
            return False

    def _creation_flags(self) -> int:
        return getattr(
            subprocess,
            "CREATE_NO_WINDOW",
            0,
        )