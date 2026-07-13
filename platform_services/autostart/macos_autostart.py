import plistlib
import subprocess
from pathlib import Path

from config import AppConfig
from domain.interfaces import AutostartServiceInterface
from platform_services.autostart.command_builder import (
    ApplicationCommandBuilder,
)
from utils.logger import setup_logger


class MacOSAutostartService(AutostartServiceInterface):
    def __init__(self) -> None:
        self._logger = setup_logger()

        self._launch_agents_dir = (
            Path.home()
            / "Library"
            / "LaunchAgents"
        )

        self._plist_path = (
            self._launch_agents_dir
            / f"{AppConfig.MACOS_LAUNCH_AGENT_LABEL}.plist"
        )

        self._user_domain = f"gui/{self._get_user_id()}"

    def enable(self) -> bool:
        AppConfig.prepare_dirs()

        self._launch_agents_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        plist_data = {
            "Label": AppConfig.MACOS_LAUNCH_AGENT_LABEL,
            "ProgramArguments": (
                ApplicationCommandBuilder.build_arguments()
            ),
            "WorkingDirectory": str(
                AppConfig.BASE_DIR.resolve()
            ),
            "RunAtLoad": True,
            "KeepAlive": False,
            "ProcessType": "Interactive",
            "StandardOutPath": str(
                AppConfig.AUTOSTART_STDOUT_LOG.resolve()
            ),
            "StandardErrorPath": str(
                AppConfig.AUTOSTART_STDERR_LOG.resolve()
            ),
        }

        try:
            self.disable()

            with self._plist_path.open("wb") as plist_file:
                plistlib.dump(
                    plist_data,
                    plist_file,
                    sort_keys=False,
                )

            self._plist_path.chmod(0o644)

            result = subprocess.run(
                [
                    "launchctl",
                    "bootstrap",
                    self._user_domain,
                    str(self._plist_path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )

            if result.returncode != 0:
                self._logger.error(
                    "Unable to enable macOS autostart: %s",
                    result.stderr.strip(),
                )
                return False

            self._logger.info(
                "macOS autostart enabled: %s",
                self._plist_path,
            )

            return True

        except (
            OSError,
            subprocess.SubprocessError,
        ) as error:
            self._logger.exception(
                "Unable to enable macOS autostart: %s",
                error,
            )
            return False

    def disable(self) -> bool:
        success = True

        if self._plist_path.exists():
            result = subprocess.run(
                [
                    "launchctl",
                    "bootout",
                    self._user_domain,
                    str(self._plist_path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )

            # Если агент не загружен, bootout может вернуть ошибку.
            # Это не мешает удалить plist.
            if result.returncode != 0:
                self._logger.info(
                    "LaunchAgent was not loaded or could not be unloaded: %s",
                    result.stderr.strip(),
                )

            try:
                self._plist_path.unlink()
            except OSError as error:
                self._logger.error(
                    "Unable to remove LaunchAgent plist: %s",
                    error,
                )
                success = False

        return success

    def is_enabled(self) -> bool:
        return self._plist_path.exists()

    def _get_user_id(self) -> int:
        result = subprocess.run(
            ["id", "-u"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )

        return int(result.stdout.strip())