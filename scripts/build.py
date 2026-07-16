#!/usr/bin/env python3

import platform
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"

APP_NAME = "AntiArchiveScanner"
UPDATER_NAME = "AntiArchiveScannerUpdater"

APP_ENTRY_POINT = PROJECT_ROOT / "app.py"
UPDATER_ENTRY_POINT = PROJECT_ROOT / "updater.py"


def remove_previous_build() -> None:
    for directory in (
        DIST_DIR,
        BUILD_DIR,
    ):
        if directory.exists():
            shutil.rmtree(directory)

    for spec_file in PROJECT_ROOT.glob("*.spec"):
        try:
            spec_file.unlink()
        except OSError:
            pass


def build_application() -> int:
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--onedir",
        "--name",
        APP_NAME,
        "--hidden-import",
        "watchdog.events",
        "--hidden-import",
        "watchdog.observers",
        "--hidden-import",
        "watchdog.observers.fsevents",
        "--hidden-import",
        "watchdog.observers.kqueue",
        "--hidden-import",
        "watchdog.observers.read_directory_changes",
        "--hidden-import",
        "tkinter",
        "--hidden-import",
        "tkinter.messagebox",
    ]

    icon_path = _application_icon()

    if icon_path is not None:
        command.extend(
            [
                "--icon",
                str(icon_path),
            ]
        )

    command.append(
        str(APP_ENTRY_POINT)
    )

    return _run_build_command(
        command=command,
        description="Сборка основной программы",
    )


def build_updater() -> int:
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--onedir",
        "--name",
        UPDATER_NAME,
        "--hidden-import",
        "tkinter",
        "--hidden-import",
        "tkinter.messagebox",
    ]

    icon_path = _updater_icon()

    if icon_path is not None:
        command.extend(
            [
                "--icon",
                str(icon_path),
            ]
        )

    command.append(
        str(UPDATER_ENTRY_POINT)
    )

    return _run_build_command(
        command=command,
        description="Сборка программы обновления",
    )


def _application_icon() -> Path | None:
    if platform.system() == "Windows":
        icon = (
            PROJECT_ROOT
            / "resources"
            / "icon.ico"
        )

        return icon if icon.exists() else None

    if platform.system() == "Darwin":
        icon = (
            PROJECT_ROOT
            / "resources"
            / "icon.icns"
        )

        return icon if icon.exists() else None

    return None


def _updater_icon() -> Path | None:
    if platform.system() == "Windows":
        updater_icon = (
            PROJECT_ROOT
            / "resources"
            / "update.ico"
        )

        if updater_icon.exists():
            return updater_icon

        return _application_icon()

    if platform.system() == "Darwin":
        updater_icon = (
            PROJECT_ROOT
            / "resources"
            / "update.icns"
        )

        if updater_icon.exists():
            return updater_icon

        return _application_icon()

    return None


def _run_build_command(
    command: list[str],
    description: str,
) -> int:
    print()
    print("=" * 60)
    print(description)
    print("=" * 60)
    print(" ".join(command))
    print()

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        check=False,
    )

    return result.returncode


def verify_application_build() -> bool:
    current_system = platform.system()

    if current_system == "Windows":
        executable_path = (
            DIST_DIR
            / APP_NAME
            / f"{APP_NAME}.exe"
        )

        return _verify_file(
            executable_path,
            "Основной Windows EXE",
        )

    if current_system == "Darwin":
        application_path = (
            DIST_DIR
            / f"{APP_NAME}.app"
        )

        executable_path = (
            application_path
            / "Contents"
            / "MacOS"
            / APP_NAME
        )

        return (
            _verify_directory(
                application_path,
                "Основное macOS-приложение",
            )
            and _verify_file(
                executable_path,
                "Основной macOS-бинарник",
            )
        )

    return False


def verify_updater_build() -> bool:
    current_system = platform.system()

    if current_system == "Windows":
        executable_path = (
            DIST_DIR
            / UPDATER_NAME
            / f"{UPDATER_NAME}.exe"
        )

        return _verify_file(
            executable_path,
            "Windows updater",
        )

    if current_system == "Darwin":
        application_path = (
            DIST_DIR
            / f"{UPDATER_NAME}.app"
        )

        executable_path = (
            application_path
            / "Contents"
            / "MacOS"
            / UPDATER_NAME
        )

        return (
            _verify_directory(
                application_path,
                "macOS updater application",
            )
            and _verify_file(
                executable_path,
                "macOS updater binary",
            )
        )

    return False


def _verify_file(
    file_path: Path,
    description: str,
) -> bool:
    if not file_path.exists():
        print(
            f"{description} не найден:",
            file_path,
        )
        return False

    if not file_path.is_file():
        print(
            f"{description} не является файлом:",
            file_path,
        )
        return False

    if file_path.stat().st_size == 0:
        print(
            f"{description} пуст:",
            file_path,
        )
        return False

    print()
    print(f"{description}:")
    print(file_path)

    return True


def _verify_directory(
    directory_path: Path,
    description: str,
) -> bool:
    if not directory_path.exists():
        print(
            f"{description} не найден:",
            directory_path,
        )
        return False

    if not directory_path.is_dir():
        print(
            f"{description} не является каталогом:",
            directory_path,
        )
        return False

    print()
    print(f"{description}:")
    print(directory_path)

    return True


def build() -> int:
    current_system = platform.system()

    print("=" * 60)
    print("Сборка AntiArchiveScanner")
    print("=" * 60)
    print("Платформа:", current_system)
    print("Архитектура:", platform.machine())
    print("Python:", platform.python_version())

    if current_system not in {
        "Windows",
        "Darwin",
    }:
        print(
            "Сборка поддерживается только "
            "на Windows и macOS."
        )
        return 1

    if not APP_ENTRY_POINT.exists():
        print(
            "Не найден основной файл:",
            APP_ENTRY_POINT,
        )
        return 1

    if not UPDATER_ENTRY_POINT.exists():
        print(
            "Не найден updater:",
            UPDATER_ENTRY_POINT,
        )
        return 1

    remove_previous_build()

    application_result = (
        build_application()
    )

    if application_result != 0:
        print()
        print(
            "Сборка основной программы "
            "завершилась ошибкой."
        )
        return application_result

    updater_result = build_updater()

    if updater_result != 0:
        print()
        print(
            "Сборка программы обновления "
            "завершилась ошибкой."
        )
        return updater_result

    if not verify_application_build():
        print()
        print(
            "Основная программа собрана, "
            "но ожидаемые файлы не найдены."
        )
        return 1

    if not verify_updater_build():
        print()
        print(
            "Updater собран, "
            "но ожидаемые файлы не найдены."
        )
        return 1

    print()
    print("=" * 60)
    print("Сборка завершена успешно")
    print("=" * 60)

    if current_system == "Windows":
        print()
        print("Основная программа:")
        print(
            DIST_DIR
            / APP_NAME
            / f"{APP_NAME}.exe"
        )

        print()
        print("Программа обновления:")
        print(
            DIST_DIR
            / UPDATER_NAME
            / f"{UPDATER_NAME}.exe"
        )

    else:
        print()
        print("Основная программа:")
        print(
            DIST_DIR
            / f"{APP_NAME}.app"
        )

        print()
        print("Программа обновления:")
        print(
            DIST_DIR
            / f"{UPDATER_NAME}.app"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(build())