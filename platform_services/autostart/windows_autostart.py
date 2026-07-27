import platform

from config import AppConfig
from domain.interfaces import (
    AutostartServiceInterface,
)
from platform_services.autostart.command_builder import (
    ApplicationCommandBuilder,
)
from utils.logger import setup_logger


class WindowsAutostartService(
    AutostartServiceInterface
):
    REGISTRY_PATH = (
        r"Software\Microsoft\Windows"
        r"\CurrentVersion\Run"
    )

    def __init__(
        self,
    ) -> None:
        self._logger = (
            setup_logger()
        )

    def enable(
        self,
    ) -> bool:
        if not self._is_windows():
            self._logger.error(
                "Windows autostart service "
                "was used on a non-Windows "
                "platform."
            )

            return False

        try:
            import winreg

            command = (
                ApplicationCommandBuilder
                .build_windows_command()
            )

            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                self.REGISTRY_PATH,
                0,
                winreg.KEY_SET_VALUE,
            ) as registry_key:
                winreg.SetValueEx(
                    registry_key,
                    AppConfig
                    .AUTOSTART_TASK_NAME,
                    0,
                    winreg.REG_SZ,
                    command,
                )

            if not self.is_enabled():
                self._logger.error(
                    "Windows autostart "
                    "registry value was "
                    "written but validation "
                    "failed."
                )

                return False

            self._logger.info(
                "Windows autostart "
                "enabled: %s",
                command,
            )

            return True

        except (
            OSError,
            ImportError,
        ) as error:
            self._logger.exception(
                "Unable to enable "
                "Windows autostart: %s",
                error,
            )

            return False

    def disable(
        self,
    ) -> bool:
        if not self._is_windows():
            return False

        try:
            import winreg

            try:
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    self.REGISTRY_PATH,
                    0,
                    winreg.KEY_SET_VALUE,
                ) as registry_key:
                    winreg.DeleteValue(
                        registry_key,
                        AppConfig
                        .AUTOSTART_TASK_NAME,
                    )

            except FileNotFoundError:
                # Ключ или значение уже
                # отсутствует.
                pass

            if self.is_enabled():
                self._logger.error(
                    "Unable to disable "
                    "Windows autostart: "
                    "registry value still "
                    "exists."
                )

                return False

            self._logger.info(
                "Windows autostart "
                "disabled."
            )

            return True

        except (
            OSError,
            ImportError,
        ) as error:
            self._logger.exception(
                "Unable to disable "
                "Windows autostart: %s",
                error,
            )

            return False

    def is_enabled(
        self,
    ) -> bool:
        if not self._is_windows():
            return False

        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.REGISTRY_PATH,
                0,
                winreg.KEY_READ,
            ) as registry_key:
                value, value_type = (
                    winreg.QueryValueEx(
                        registry_key,
                        AppConfig
                        .AUTOSTART_TASK_NAME,
                    )
                )

        except (
            FileNotFoundError,
            OSError,
            ImportError,
        ):
            return False

        if (
            value_type
            != winreg.REG_SZ
        ):
            return False

        expected_command = (
            ApplicationCommandBuilder
            .build_windows_command()
        )

        return (
            self._normalize_command(
                value
            )
            == self._normalize_command(
                expected_command
            )
        )

    def current_command(
        self,
    ) -> str | None:
        if not self._is_windows():
            return None

        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.REGISTRY_PATH,
                0,
                winreg.KEY_READ,
            ) as registry_key:
                value, _ = (
                    winreg.QueryValueEx(
                        registry_key,
                        AppConfig
                        .AUTOSTART_TASK_NAME,
                    )
                )

            return str(
                value
            )

        except (
            FileNotFoundError,
            OSError,
            ImportError,
        ):
            return None

    @staticmethod
    def _normalize_command(
        command: str,
    ) -> str:
        return (
            " ".join(
                command.split()
            )
            .strip()
            .lower()
        )

    @staticmethod
    def _is_windows(
    ) -> bool:
        return (
            platform.system()
            == "Windows"
        )