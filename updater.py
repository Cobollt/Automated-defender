import argparse
import os
import platform
import shutil
import subprocess
import tempfile
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

from infrastructure.update import (
    APP_NAME,
    UPDATE_MANIFEST_URL,
    UpdateClient,
    UpdateError,
    UpdateManifest,
    detect_installed_version,
    is_newer_version,
)


PROCESS_WAIT_TIMEOUT_SECONDS = 30.0
PROCESS_WAIT_INTERVAL_SECONDS = 0.5


def parse_arguments(
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "AntiArchiveScanner updater"
        )
    )

    parser.add_argument(
        "--pid",
        type=int,
        default=None,
        help=(
            "PID основного приложения, "
            "завершения которого нужно "
            "дождаться перед установкой."
        ),
    )

    return parser.parse_args()


def process_exists(
    pid: int,
) -> bool:
    if pid <= 0:
        return False

    try:
        os.kill(
            pid,
            0,
        )

    except ProcessLookupError:
        return False

    except PermissionError:
        return True

    except OSError:
        return False

    return True


def wait_for_process_exit(
    pid: int,
    timeout_seconds: float = (
        PROCESS_WAIT_TIMEOUT_SECONDS
    ),
) -> None:
    deadline = (
        time.monotonic()
        + timeout_seconds
    )

    while (
        time.monotonic()
        < deadline
    ):
        if not process_exists(
            pid
        ):
            return

        time.sleep(
            PROCESS_WAIT_INTERVAL_SECONDS
        )

    raise UpdateError(
        "Основное приложение "
        "не завершилось "
        "в установленное время."
    )


def update_file_suffix(
) -> str:
    system_name = (
        platform.system()
    )

    if system_name == "Windows":
        return ".exe"

    if system_name == "Darwin":
        return ".dmg"

    raise UpdateError(
        "Обновление не поддерживается "
        "на этой операционной системе."
    )


def installer_filename(
    manifest: UpdateManifest,
) -> str:
    return (
        f"{APP_NAME}-"
        f"{manifest.version}"
        f"{update_file_suffix()}"
    )


def prepare_download_directory(
    version: str,
) -> Path:
    update_root = (
        Path(
            tempfile.gettempdir()
        )
        / APP_NAME
        / "updates"
    )

    update_directory = (
        update_root
        / version
    )

    if update_directory.exists():
        shutil.rmtree(
            update_directory,
            ignore_errors=True,
        )

    update_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return update_directory


def launch_windows_installer(
    installer_path: Path,
) -> None:
    subprocess.Popen(
        [
            str(
                installer_path
            ),
            "/SILENT",
            "/CLOSEAPPLICATIONS",
        ],
        cwd=installer_path.parent,
        creationflags=(
            getattr(
                subprocess,
                "DETACHED_PROCESS",
                0,
            )
            |
            getattr(
                subprocess,
                "CREATE_NEW_PROCESS_GROUP",
                0,
            )
        ),
        close_fds=True,
    )


def launch_macos_installer(
    dmg_path: Path,
) -> None:
    subprocess.Popen(
        [
            "open",
            str(
                dmg_path
            ),
        ],
        cwd=dmg_path.parent,
        start_new_session=True,
        close_fds=True,
    )


def launch_installer(
    update_path: Path,
) -> None:
    system_name = (
        platform.system()
    )

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
        "не поддерживается "
        "на этой ОС."
    )


class UpdaterWindow:
    def __init__(
        self,
        application_pid: (
            int | None
        ) = None,
    ) -> None:
        self._application_pid = (
            application_pid
        )

        self._root = tk.Tk()
        self._root.withdraw()

        self._client = UpdateClient(
            UPDATE_MANIFEST_URL
        )

        self._current_version = (
            detect_installed_version()
        )

    def run(
        self,
    ) -> int:
        try:
            manifest = (
                self._client
                .fetch_manifest()
            )

            platform_update = (
                manifest
                .platform_update()
            )

            if not is_newer_version(
                current_version=(
                    self._current_version
                ),
                remote_version=(
                    manifest.version
                ),
            ):
                messagebox.showinfo(
                    title=(
                        f"{APP_NAME} Update"
                    ),
                    message=(
                        "Установлена "
                        "актуальная версия."
                        "\n\n"
                        "Текущая версия: "
                        f"{self._current_version}"
                    ),
                    parent=self._root,
                )

                return 0

            confirmed = (
                messagebox.askyesno(
                    title=(
                        f"{APP_NAME} Update"
                    ),
                    message=(
                        "Доступно обновление."
                        "\n\n"
                        "Текущая версия: "
                        f"{self._current_version}"
                        "\n"
                        "Новая версия: "
                        f"{manifest.version}"
                        "\n\n"
                        "Загрузить обновление?"
                    ),
                    parent=self._root,
                )
            )

            if not confirmed:
                return 0

            update_path = (
                self._download(
                    manifest=manifest,
                    download_url=(
                        platform_update.url
                    ),
                    sha256=(
                        platform_update.sha256
                    ),
                )
            )

            install_confirmed = (
                messagebox.askyesno(
                    title=(
                        f"{APP_NAME} Update"
                    ),
                    message=(
                        "Обновление загружено "
                        "и прошло проверку "
                        "SHA-256."
                        "\n\n"
                        "Начать установку?"
                    ),
                    parent=self._root,
                )
            )

            if not install_confirmed:
                return 0

            self._wait_for_application()

            launch_installer(
                update_path
            )

            messagebox.showinfo(
                title=(
                    f"{APP_NAME} Update"
                ),
                message=(
                    "Установщик обновления "
                    "запущен."
                ),
                parent=self._root,
            )

            return 0

        except UpdateError as error:
            messagebox.showerror(
                title=(
                    f"{APP_NAME} Update"
                ),
                message=str(
                    error
                ),
                parent=self._root,
            )

            return 1

        except Exception as error:
            messagebox.showerror(
                title=(
                    f"{APP_NAME} Update"
                ),
                message=(
                    "Непредвиденная ошибка "
                    "обновления: "
                    f"{error}"
                ),
                parent=self._root,
            )

            return 1

        finally:
            try:
                self._root.destroy()

            except tk.TclError:
                pass

    def _download(
        self,
        manifest: UpdateManifest,
        download_url: str,
        sha256: str,
    ) -> Path:
        download_directory = (
            prepare_download_directory(
                manifest.version
            )
        )

        update_path = (
            download_directory
            / installer_filename(
                manifest
            )
        )

        self._client.download_update(
            url=download_url,
            expected_sha256=sha256,
            destination=update_path,
        )

        return update_path

    def _wait_for_application(
        self,
    ) -> None:
        if (
            self._application_pid
            is None
        ):
            return

        if (
            self._application_pid
            == os.getpid()
        ):
            raise UpdateError(
                "Updater получил "
                "собственный PID вместо "
                "PID основной программы."
            )

        wait_for_process_exit(
            self._application_pid
        )


def main(
) -> int:
    arguments = (
        parse_arguments()
    )

    updater = UpdaterWindow(
        application_pid=(
            arguments.pid
        )
    )

    return updater.run()


if __name__ == "__main__":
    raise SystemExit(
        main()
    )