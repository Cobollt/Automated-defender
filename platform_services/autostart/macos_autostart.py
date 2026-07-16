import os
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

        self._user_domain = (
            f"gui/{os.getuid()}"
        )

    def enable(self) -> bool:
        AppConfig.prepare_dirs()

        self._launch_agents_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        plist_data = {
            "Label": AppConfig.MACOS_LAUNCH_AGENT_LABEL,
            "ProgramArguments": (
                ApplicationCommandBuilder
                .build_macos_program_arguments()
            ),
            "WorkingDirectory": str(
                ApplicationCommandBuilder
                .working_directory()
            ),
            "RunAtLoad": True,
            "KeepAlive": False,
            "ProcessType": "Interactive",
            "LimitLoadToSessionType": "Aqua",
            "StandardOutPath": str(
                AppConfig.AUTOSTART_STDOUT_LOG.resolve()
            ),
            "StandardErrorPath": str(
                AppConfig.AUTOSTART_STDERR_LOG.resolve()
            ),
        }

        try:
            self._unload_existing_agent()

            with self._plist_path.open(
                "wb"
            ) as plist_file:
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
                    (
                        result.stderr.strip()
                        or result.stdout.strip()
                    ),
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

        self._unload_existing_agent()

        if self._plist_path.exists():
            try:
                self._plist_path.unlink()

            except OSError as error:
                self._logger.error(
                    "Unable to remove LaunchAgent plist: %s",
                    error,
                )
                success = False

        if success:
            self._logger.info(
                "macOS autostart disabled"
            )

        return success

    def is_enabled(self) -> bool:
        if not self._plist_path.exists():
            return False

        try:
            result = subprocess.run(
                [
                    "launchctl",
                    "print",
                    (
                        f"{self._user_domain}/"
                        f"{AppConfig.MACOS_LAUNCH_AGENT_LABEL}"
                    ),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

            return result.returncode == 0

        except (
            OSError,
            subprocess.SubprocessError,
        ):
            return False

    def _unload_existing_agent(self) -> None:
        try:
            result = subprocess.run(
                [
                    "launchctl",
                    "bootout",
                    (
                        f"{self._user_domain}/"
                        f"{AppConfig.MACOS_LAUNCH_AGENT_LABEL}"
                    ),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )

            if result.returncode != 0:
                self._logger.debug(
                    "LaunchAgent was not loaded: %s",
                    (
                        result.stderr.strip()
                        or result.stdout.strip()
                    ),
                )

        except (
            OSError,
            subprocess.SubprocessError,
        ) as error:
            self._logger.debug(
                "Unable to unload existing LaunchAgent: %s",
                error,
            )