import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import tkinter as tk
import urllib.error
import urllib.request
from pathlib import Path
from tkinter import messagebox
from typing import Any


APP_NAME = "AntiArchiveScanner"
CURRENT_VERSION = "1.0.0"

UPDATE_MANIFEST_URL = (
    "https://github.com/Cobollt/Automated-defender.git"
    "update-manifest.json"
)

DOWNLOAD_TIMEOUT_SECONDS = 60
BUFFER_SIZE = 1024 * 1024


class UpdateError(Exception):
    pass


class Version:
    def __init__(self, value: str) -> None:
        normalized = value.strip().lstrip("v")

        if not normalized:
            raise ValueError("Пустая версия.")

        try:
            self.parts = tuple(
                int(part)
                for part in normalized.split(".")
            )
        except ValueError as error:
            raise ValueError(
                f"Некорректная версия: {value}"
            ) from error

    def __lt__(self, other: "Version") -> bool:
        length = max(
            len(self.parts),
            len(other.parts),
        )

        left = self.parts + (0,) * (
            length - len(self.parts)
        )

        right = other.parts + (0,) * (
            length - len(other.parts)
        )

        return left < right


class UpdateManifest:
    def __init__(
        self,
        data: dict[str, Any],
    ) -> None:
        self.version = str(
            data.get("version", "")
        ).strip()

        if not self.version:
            raise UpdateError(
                "В манифесте отсутствует версия."
            )

        platform_key = self._platform_key()

        platform_data = data.get(
            platform_key
        )

        if not isinstance(
            platform_data,
            dict,
        ):
            raise UpdateError(
                "В манифесте отсутствует "
                f"секция для {platform_key}."
            )

        self.download_url = str(
            platform_data.get("url", "")
        ).strip()

        self.sha256 = str(
            platform_data.get("sha256", "")
        ).strip().lower()

        if not self.download_url:
            raise UpdateError(
                "В манифесте отсутствует URL обновления."
            )

        if len(self.sha256) != 64:
            raise UpdateError(
                "В манифесте указан некорректный SHA-256."
            )

    @staticmethod
    def _platform_key() -> str:
        system_name = platform.system()

        if system_name == "Windows":
            return "windows"

        if system_name == "Darwin":
            return "macos"

        raise UpdateError(
            "Обновление поддерживается только "
            "на Windows и macOS."
        )


class UpdateClient:
    def __init__(
        self,
        manifest_url: str,
    ) -> None:
        self._manifest_url = manifest_url

    def fetch_manifest(
        self,
    ) -> UpdateManifest:
        try:
            with urllib.request.urlopen(
                self._manifest_url,
                timeout=DOWNLOAD_TIMEOUT_SECONDS,
            ) as response:
                raw_data = response.read()

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as error:
            raise UpdateError(
                "Не удалось загрузить "
                f"манифест обновления: {error}"
            ) from error

        try:
            data = json.loads(
                raw_data.decode("utf-8")
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise UpdateError(
                "Манифест обновления повреждён."
            ) from error

        if not isinstance(data, dict):
            raise UpdateError(
                "Манифест имеет некорректный формат."
            )

        return UpdateManifest(data)

    def download_update(
        self,
        manifest: UpdateManifest,
        destination: Path,
    ) -> None:
        try:
            with urllib.request.urlopen(
                manifest.download_url,
                timeout=DOWNLOAD_TIMEOUT_SECONDS,
            ) as response:
                with destination.open(
                    "wb"
                ) as output_file:
                    while True:
                        chunk = response.read(
                            BUFFER_SIZE
                        )

                        if not chunk:
                            break

                        output_file.write(chunk)

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as error:
            raise UpdateError(
                "Не удалось загрузить обновление: "
                f"{error}"
            ) from error

        actual_sha256 = calculate_sha256(
            destination
        )

        if actual_sha256 != manifest.sha256:
            destination.unlink(
                missing_ok=True
            )

            raise UpdateError(
                "SHA-256 обновления не совпадает. "
                "Файл удалён."
            )


def calculate_sha256(
    file_path: Path,
) -> str:
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        while True:
            chunk = file.read(
                BUFFER_SIZE
            )

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def is_update_available(
    remote_version: str,
) -> bool:
    try:
        current = Version(
            CURRENT_VERSION
        )
        remote = Version(
            remote_version
        )

    except ValueError as error:
        raise UpdateError(
            str(error)
        ) from error

    return current < remote


def stop_main_application() -> None:
    system_name = platform.system()

    if system_name == "Windows":
        subprocess.run(
            [
                "taskkill.exe",
                "/F",
                "/IM",
                f"{APP_NAME}.exe",
            ],
            capture_output=True,
            text=True,
            check=False,
            creationflags=getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0,
            ),
        )

        return

    if system_name == "Darwin":
        subprocess.run(
            [
                "pkill",
                "-x",
                APP_NAME,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        return

    raise UpdateError(
        "Остановка приложения "
        "не поддерживается на этой ОС."
    )


def launch_windows_installer(
    installer_path: Path,
) -> None:
    stop_main_application()

    subprocess.Popen(
        [
            str(installer_path),
            "/SILENT",
            "/CLOSEAPPLICATIONS",
            "/RESTARTAPPLICATIONS",
        ],
        cwd=installer_path.parent,
        creationflags=getattr(
            subprocess,
            "DETACHED_PROCESS",
            0,
        )
        | getattr(
            subprocess,
            "CREATE_NEW_PROCESS_GROUP",
            0,
        ),
    )


def launch_macos_installer(
    dmg_path: Path,
) -> None:
    stop_main_application()

    subprocess.Popen(
        [
            "open",
            str(dmg_path),
        ],
        cwd=dmg_path.parent,
        start_new_session=True,
    )


def launch_installer(
    update_path: Path,
) -> None:
    system_name = platform.system()

    if system_name == "Windows":
        launch_windows_installer(
            update_path
        )
        return

    if system_name == "Darwin":
        launch_macos_installer(
            update_path
        )
        return

    raise UpdateError(
        "Установка обновлений "
        "не поддерживается на этой ОС."
    )


def update_file_suffix() -> str:
    system_name = platform.system()

    if system_name == "Windows":
        return ".exe"

    if system_name == "Darwin":
        return ".dmg"

    raise UpdateError(
        "Обновление не поддерживается "
        "на этой ОС."
    )


class UpdaterWindow:
    def __init__(self) -> None:
        self._root = tk.Tk()
        self._root.withdraw()

        self._client = UpdateClient(
            UPDATE_MANIFEST_URL
        )

    def run(self) -> int:
        try:
            manifest = (
                self._client.fetch_manifest()
            )

            if not is_update_available(
                manifest.version
            ):
                messagebox.showinfo(
                    title=f"{APP_NAME} Update",
                    message=(
                        "Установлена актуальная версия.\n\n"
                        f"Текущая версия: {CURRENT_VERSION}"
                    ),
                )

                return 0

            confirmed = messagebox.askyesno(
                title=f"{APP_NAME} Update",
                message=(
                    "Доступно обновление.\n\n"
                    f"Текущая версия: {CURRENT_VERSION}\n"
                    f"Новая версия: {manifest.version}\n\n"
                    "Загрузить и установить обновление?"
                ),
            )

            if not confirmed:
                return 0

            update_path = self._download(
                manifest
            )

            install_confirmed = (
                messagebox.askyesno(
                    title=f"{APP_NAME} Update",
                    message=(
                        "Обновление загружено и проверено.\n\n"
                        "Основное приложение будет закрыто.\n"
                        "Начать установку?"
                    ),
                )
            )

            if not install_confirmed:
                return 0

            launch_installer(
                update_path
            )

            messagebox.showinfo(
                title=f"{APP_NAME} Update",
                message=(
                    "Установщик обновления запущен.\n"
                    "Программа обновления будет закрыта."
                ),
            )

            return 0

        except UpdateError as error:
            messagebox.showerror(
                title=f"{APP_NAME} Update",
                message=str(error),
            )

            return 1

        finally:
            self._root.destroy()

    def _download(
        self,
        manifest: UpdateManifest,
    ) -> Path:
        suffix = update_file_suffix()

        download_dir = (
            Path(tempfile.gettempdir())
            / APP_NAME
            / "updates"
            / manifest.version
        )

        if download_dir.exists():
            shutil.rmtree(
                download_dir,
                ignore_errors=True,
            )

        download_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        update_path = (
            download_dir
            / f"{APP_NAME}-Update{suffix}"
        )

        self._client.download_update(
            manifest=manifest,
            destination=update_path,
        )

        return update_path


def main() -> int:
    updater = UpdaterWindow()
    return updater.run()


if __name__ == "__main__":
    raise SystemExit(main())