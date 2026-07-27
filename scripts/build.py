#!/usr/bin/env python3

import platform
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

APP_NAME = (
    "AntiArchiveScanner"
)

UPDATER_NAME = (
    "AntiArchiveScannerUpdater"
)

APP_ENTRY_POINT = (
    PROJECT_ROOT
    / "app.py"
)

UPDATER_ENTRY_POINT = (
    PROJECT_ROOT
    / "updater.py"
)

BUILD_DIR = (
    PROJECT_ROOT
    / "build"
)

DIST_DIR = (
    PROJECT_ROOT
    / "dist"
)


class BuildError(
    RuntimeError
):
    pass


def print_header(
    title: str,
) -> None:
    print()
    print(
        "=" * 60
    )
    print(
        title
    )
    print(
        "=" * 60
    )


def validate_platform(
) -> str:
    system_name = (
        platform.system()
    )

    if (
        system_name
        not in {
            "Windows",
            "Darwin",
        }
    ):
        raise BuildError(
            "PyInstaller-сборка "
            "проекта поддерживается "
            "только на Windows "
            "и macOS. "
            "Текущая система: "
            f"{system_name}"
        )

    return system_name


def validate_project(
) -> None:
    for path in (
        APP_ENTRY_POINT,
        UPDATER_ENTRY_POINT,
    ):
        if not path.exists():
            raise BuildError(
                "Не найден "
                "обязательный файл: "
                f"{path}"
            )


def clean_previous_build(
) -> None:
    for directory in (
        BUILD_DIR,
        DIST_DIR,
    ):
        if directory.exists():
            shutil.rmtree(
                directory
            )

    for spec_file in (
        PROJECT_ROOT
        .glob(
            "*.spec"
        )
    ):
        spec_file.unlink(
            missing_ok=True
        )


def application_icon(
) -> Path | None:
    system_name = (
        platform.system()
    )

    if (
        system_name
        == "Windows"
    ):
        icon_path = (
            PROJECT_ROOT
            / "resources"
            / "icon.ico"
        )

    else:
        icon_path = (
            PROJECT_ROOT
            / "resources"
            / "icon.icns"
        )

    if icon_path.exists():
        return icon_path

    return None


def updater_icon(
) -> Path | None:
    system_name = (
        platform.system()
    )

    if (
        system_name
        == "Windows"
    ):
        icon_path = (
            PROJECT_ROOT
            / "resources"
            / "update.ico"
        )

    else:
        icon_path = (
            PROJECT_ROOT
            / "resources"
            / "update.icns"
        )

    if icon_path.exists():
        return icon_path

    return application_icon()


def common_pyinstaller_arguments(
    name: str,
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--onedir",
        "--name",
        name,
    ]


def build_application(
) -> None:
    command = (
        common_pyinstaller_arguments(
            APP_NAME
        )
    )

    command.extend(
        [
            "--hidden-import",
            "watchdog.events",

            "--hidden-import",
            "watchdog.observers",

            "--hidden-import",
            "tkinter",

            "--hidden-import",
            "tkinter.messagebox",
        ]
    )

    system_name = (
        platform.system()
    )

    if (
        system_name
        == "Darwin"
    ):
        command.extend(
            [
                "--hidden-import",
                (
                    "watchdog.observers."
                    "fsevents"
                ),

                "--hidden-import",
                (
                    "watchdog.observers."
                    "kqueue"
                ),
            ]
        )

    elif (
        system_name
        == "Windows"
    ):
        command.extend(
            [
                "--hidden-import",
                (
                    "watchdog.observers."
                    "read_directory_changes"
                ),
            ]
        )

    icon_path = (
        application_icon()
    )

    if (
        icon_path
        is not None
    ):
        command.extend(
            [
                "--icon",
                str(
                    icon_path
                ),
            ]
        )

    command.append(
        str(
            APP_ENTRY_POINT
        )
    )

    run_pyinstaller(
        command,
        "Сборка основной программы",
    )


def build_updater(
) -> None:
    command = (
        common_pyinstaller_arguments(
            UPDATER_NAME
        )
    )

    command.extend(
        [
            "--hidden-import",
            "tkinter",

            "--hidden-import",
            "tkinter.messagebox",

            "--hidden-import",
            "packaging.version",
        ]
    )

    icon_path = (
        updater_icon()
    )

    if (
        icon_path
        is not None
    ):
        command.extend(
            [
                "--icon",
                str(
                    icon_path
                ),
            ]
        )

    command.append(
        str(
            UPDATER_ENTRY_POINT
        )
    )

    run_pyinstaller(
        command,
        "Сборка программы обновления",
    )


def run_pyinstaller(
    command: list[str],
    description: str,
) -> None:
    print_header(
        description
    )

    print(
        " ".join(
            command
        )
    )

    print()

    result = (
        subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            check=False,
        )
    )

    if (
        result.returncode
        != 0
    ):
        raise BuildError(
            f"{description} "
            "завершено с ошибкой. "
            "Код возврата: "
            f"{result.returncode}"
        )


def verify_build(
) -> None:
    system_name = (
        platform.system()
    )

    if (
        system_name
        == "Windows"
    ):
        app_path = (
            DIST_DIR
            / APP_NAME
            / f"{APP_NAME}.exe"
        )

        updater_path = (
            DIST_DIR
            / UPDATER_NAME
            / f"{UPDATER_NAME}.exe"
        )

        verify_file(
            app_path,
            (
                "Windows-приложение"
            ),
        )

        verify_file(
            updater_path,
            (
                "Windows-updater"
            ),
        )

    else:
        app_bundle = (
            DIST_DIR
            / f"{APP_NAME}.app"
        )

        updater_bundle = (
            DIST_DIR
            / f"{UPDATER_NAME}.app"
        )

        verify_directory(
            app_bundle,
            (
                "macOS-приложение"
            ),
        )

        verify_directory(
            updater_bundle,
            (
                "macOS-updater"
            ),
        )

        verify_file(
            app_bundle
            / "Contents"
            / "MacOS"
            / APP_NAME,
            (
                "macOS-бинарник "
                "приложения"
            ),
        )

        verify_file(
            updater_bundle
            / "Contents"
            / "MacOS"
            / UPDATER_NAME,
            (
                "macOS-бинарник "
                "updater"
            ),
        )


def verify_file(
    path: Path,
    description: str,
) -> None:
    if not path.exists():
        raise BuildError(
            f"{description} "
            "не найден: "
            f"{path}"
        )

    if not path.is_file():
        raise BuildError(
            f"{description} "
            "не является файлом: "
            f"{path}"
        )

    if (
        path.stat().st_size
        <= 0
    ):
        raise BuildError(
            f"{description} "
            "пуст: "
            f"{path}"
        )


def verify_directory(
    path: Path,
    description: str,
) -> None:
    if not path.exists():
        raise BuildError(
            f"{description} "
            "не найден: "
            f"{path}"
        )

    if not path.is_dir():
        raise BuildError(
            f"{description} "
            "не является каталогом: "
            f"{path}"
        )


def print_result(
) -> None:
    system_name = (
        platform.system()
    )

    print_header(
        "Сборка завершена успешно"
    )

    if (
        system_name
        == "Windows"
    ):
        print(
            "Приложение:",
            DIST_DIR
            / APP_NAME
            / f"{APP_NAME}.exe",
        )

        print(
            "Updater:",
            DIST_DIR
            / UPDATER_NAME
            / f"{UPDATER_NAME}.exe",
        )

    else:
        print(
            "Приложение:",
            DIST_DIR
            / f"{APP_NAME}.app",
        )

        print(
            "Updater:",
            DIST_DIR
            / f"{UPDATER_NAME}.app",
        )


def build(
) -> int:
    try:
        validate_platform()
        validate_project()

        clean_previous_build()

        build_application()

        build_updater()

        verify_build()

        print_result()

        return 0

    except (
        BuildError,
        FileNotFoundError,
        OSError,
    ) as error:
        print_header(
            "Сборка завершилась "
            "ошибкой"
        )

        print(
            error
        )

        return 1

    except KeyboardInterrupt:
        print()

        print(
            "Сборка остановлена "
            "пользователем."
        )

        return 130


if __name__ == "__main__":
    raise SystemExit(
        build()
    )