import os
import platform
import plistlib
import subprocess
from pathlib import Path

from config import AppConfig
from domain.interfaces import (
    AutostartServiceInterface,
)
from platform_services.autostart.command_builder import (
    ApplicationCommandBuilder,
)
from utils.logger import setup_logger


class MacOSAutostartService(
    AutostartServiceInterface
):
    LAUNCHCTL_TIMEOUT = 15

    def __init__(
        self,
    ) -> None:
        self._logger = (
            setup_logger()
        )

        self._launch_agents_dir = (
            Path.home()
            / "Library"
            / "LaunchAgents"
        )

        self._plist_path = (
            self._launch_agents_dir
            / (
                f"{AppConfig.MACOS_LAUNCH_AGENT_LABEL}"
                ".plist"
            )
        )

        self._user_domain = (
            f"gui/{os.getuid()}"
        )

        self._service_target = (
            f"{self._user_domain}/"
            f"{AppConfig.MACOS_LAUNCH_AGENT_LABEL}"
        )

    @property
    def plist_path(
        self,
    ) -> Path:
        return self._plist_path

    def enable(
        self,
    ) -> bool:
        if not self._is_macos():
            self._logger.error(
                "macOS autostart service "
                "was used on a non-macOS "
                "platform."
            )

            return False

        try:
            AppConfig.prepare_dirs()

            self._launch_agents_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            plist_data = (
                self._build_plist()
            )

            self._unload_existing_agent()

            self._write_plist_atomically(
                plist_data
            )

            result = (
                self._run_launchctl(
                    [
                        "bootstrap",
                        self._user_domain,
                        str(
                            self._plist_path
                        ),
                    ]
                )
            )

            if (
                result.returncode
                != 0
            ):
                self._logger.error(
                    "Unable to enable "
                    "macOS autostart: %s",
                    self._result_message(
                        result
                    ),
                )

                return False

            if not self.is_enabled():
                self._logger.error(
                    "LaunchAgent bootstrap "
                    "completed but "
                    "validation failed."
                )

                return False

            self._logger.info(
                "macOS autostart "
                "enabled: %s",
                self._plist_path,
            )

            return True

        except (
            OSError,
            subprocess.SubprocessError,
            plistlib.InvalidFileException,
        ) as error:
            self._logger.exception(
                "Unable to enable "
                "macOS autostart: %s",
                error,
            )

            return False

    def disable(
        self,
    ) -> bool:
        if not self._is_macos():
            return False

        success = True

        try:
            self._unload_existing_agent()

        except Exception:
            self._logger.exception(
                "Unable to unload "
                "LaunchAgent."
            )

            success = False

        if (
            self._plist_path.exists()
            or self._plist_path.is_symlink()
        ):
            try:
                self._plist_path.unlink()

            except OSError as error:
                self._logger.error(
                    "Unable to remove "
                    "LaunchAgent plist: %s",
                    error,
                )

                success = False

        if self.is_enabled():
            self._logger.error(
                "macOS autostart "
                "is still enabled "
                "after disable request."
            )

            return False

        if success:
            self._logger.info(
                "macOS autostart disabled."
            )

        return success

    def is_enabled(
        self,
    ) -> bool:
        if not self._is_macos():
            return False

        if not self._plist_path.exists():
            return False

        if not self._plist_matches_current_command():
            return False

        try:
            result = (
                self._run_launchctl(
                    [
                        "print",
                        self._service_target,
                    ],
                    timeout=10,
                )
            )

            return (
                result.returncode
                == 0
            )

        except (
            OSError,
            subprocess.SubprocessError,
        ):
            return False

    def _build_plist(
        self,
    ) -> dict:
        return {
            "Label": (
                AppConfig
                .MACOS_LAUNCH_AGENT_LABEL
            ),
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
            "ProcessType": (
                "Interactive"
            ),
            "LimitLoadToSessionType": (
                "Aqua"
            ),
            "StandardOutPath": str(
                AppConfig
                .AUTOSTART_STDOUT_LOG
                .resolve()
            ),
            "StandardErrorPath": str(
                AppConfig
                .AUTOSTART_STDERR_LOG
                .resolve()
            ),
        }

    def _write_plist_atomically(
        self,
        plist_data: dict,
    ) -> None:
        temporary_path = (
            self._plist_path
            .with_name(
                self._plist_path.name
                + ".tmp"
            )
        )

        temporary_path.unlink(
            missing_ok=True
        )

        try:
            with temporary_path.open(
                "wb"
            ) as plist_file:
                plistlib.dump(
                    plist_data,
                    plist_file,
                    fmt=(
                        plistlib.FMT_XML
                    ),
                    sort_keys=False,
                )

                plist_file.flush()

                os.fsync(
                    plist_file.fileno()
                )

            temporary_path.chmod(
                0o644
            )

            temporary_path.replace(
                self._plist_path
            )

            self._plist_path.chmod(
                0o644
            )

        except Exception:
            temporary_path.unlink(
                missing_ok=True
            )

            raise

    def _plist_matches_current_command(
        self,
    ) -> bool:
        try:
            with self._plist_path.open(
                "rb"
            ) as plist_file:
                plist_data = (
                    plistlib.load(
                        plist_file
                    )
                )

        except (
            OSError,
            plistlib.InvalidFileException,
        ):
            return False

        if (
            plist_data.get(
                "Label"
            )
            != (
                AppConfig
                .MACOS_LAUNCH_AGENT_LABEL
            )
        ):
            return False

        expected_arguments = (
            ApplicationCommandBuilder
            .build_macos_program_arguments()
        )

        actual_arguments = (
            plist_data.get(
                "ProgramArguments"
            )
        )

        if (
            actual_arguments
            != expected_arguments
        ):
            return False

        expected_working_directory = (
            str(
                ApplicationCommandBuilder
                .working_directory()
            )
        )

        actual_working_directory = (
            plist_data.get(
                "WorkingDirectory"
            )
        )

        return (
            actual_working_directory
            == expected_working_directory
        )

    def _unload_existing_agent(
        self,
    ) -> None:
        try:
            result = (
                self._run_launchctl(
                    [
                        "bootout",
                        self._service_target,
                    ]
                )
            )

        except (
            OSError,
            subprocess.SubprocessError,
        ) as error:
            self._logger.debug(
                "Unable to unload "
                "existing LaunchAgent: %s",
                error,
            )

            return

        if (
            result.returncode
            != 0
        ):
            self._logger.debug(
                "LaunchAgent was not "
                "loaded: %s",
                self._result_message(
                    result
                ),
            )

    def _run_launchctl(
        self,
        arguments: list[str],
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "launchctl",
                *arguments,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=(
                timeout
                or self.LAUNCHCTL_TIMEOUT
            ),
        )

    @staticmethod
    def _result_message(
        result: (
            subprocess.CompletedProcess
        ),
    ) -> str:
        return (
            result.stderr.strip()
            or result.stdout.strip()
            or (
                "launchctl returned "
                f"{result.returncode}"
            )
        )

    @staticmethod
    def _is_macos(
    ) -> bool:
        return (
            platform.system()
            == "Darwin"
        )