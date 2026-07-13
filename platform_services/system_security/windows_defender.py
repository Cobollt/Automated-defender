import os
import shutil
import subprocess
import time
from pathlib import Path

from config import AppConfig
from domain.interfaces import SystemSecurityProviderInterface
from domain.models import SystemSecurityResult
from utils.logger import setup_logger


class WindowsDefenderProvider(SystemSecurityProviderInterface):
    PROVIDER_NAME = "Microsoft Defender"

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

        executable = self._find_mpcmdrun()

        if executable is None:
            return SystemSecurityResult(
                success=False,
                provider_name=self.PROVIDER_NAME,
                file_path=file_path,
                message="MpCmdRun.exe не найден.",
            )

        try:
            process = subprocess.run(
                [
                    str(executable),
                    "-Scan",
                    "-ScanType",
                    "3",
                    "-File",
                    str(file_path),
                    "-DisableRemediation",
                    "false",

                    #str(executable),
                    #"-Scan",
                    #"-ScanType",
                    #"3",
                    #"-File",
                    #str(file_path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=AppConfig.SYSTEM_SECURITY_TIMEOUT,
                creationflags=self._creation_flags(),
            )

        except subprocess.TimeoutExpired:
            return SystemSecurityResult(
                success=False,
                provider_name=self.PROVIDER_NAME,
                file_path=file_path,
                message="Microsoft Defender не ответил вовремя.",
            )

        except OSError as error:
            self._logger.exception(
                "Unable to start Microsoft Defender"
            )

            return SystemSecurityResult(
                success=False,
                provider_name=self.PROVIDER_NAME,
                file_path=file_path,
                message=f"Ошибка запуска Defender: {error}",
            )

        self._logger.info(
            "Microsoft Defender finished with code %s for %s",
            process.returncode,
            file_path,
        )

        file_isolated = self._wait_for_file_removal(file_path)

        if file_isolated:
            return SystemSecurityResult(
                success=True,
                provider_name=self.PROVIDER_NAME,
                file_path=file_path,
                threat_detected=True,
                file_isolated=True,
                message=(
                    "Microsoft Defender обработал файл. "
                    "Файл больше не находится в исходной папке."
                ),
            )

        return SystemSecurityResult(
            success=process.returncode == 0,
            provider_name=self.PROVIDER_NAME,
            file_path=file_path,
            threat_detected=False,
            file_isolated=False,
            message=(
                "Microsoft Defender завершил проверку, "
                "но не подтвердил помещение файла в карантин."
            ),
        )

    def _find_mpcmdrun(self) -> Path | None:
        executable_from_path = shutil.which("MpCmdRun.exe")

        if executable_from_path:
            return Path(executable_from_path)

        program_data = os.environ.get(
            "ProgramData",
            r"C:\ProgramData",
        )

        platform_dir = (
            Path(program_data)
            / "Microsoft"
            / "Windows Defender"
            / "Platform"
        )

        if platform_dir.exists():
            candidates = sorted(
                platform_dir.glob("*/MpCmdRun.exe"),
                reverse=True,
            )

            if candidates:
                return candidates[0]

        program_files = os.environ.get(
            "ProgramFiles",
            r"C:\Program Files",
        )

        standard_path = (
            Path(program_files)
            / "Windows Defender"
            / "MpCmdRun.exe"
        )

        if standard_path.exists():
            return standard_path

        return None

    def _wait_for_file_removal(
        self,
        file_path: Path,
    ) -> bool:
        deadline = time.monotonic() + 5

        while time.monotonic() < deadline:
            if not file_path.exists():
                return True

            time.sleep(0.5)

        return not file_path.exists()

    def _creation_flags(self) -> int:
        return getattr(
            subprocess,
            "CREATE_NO_WINDOW",
            0,
        )