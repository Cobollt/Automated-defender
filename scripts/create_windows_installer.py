#!/usr/bin/env python3

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

APP_NAME = "AntiArchiveScanner"

DIST_DIR = PROJECT_ROOT / "dist" / APP_NAME

EXECUTABLE_PATH = (
    DIST_DIR
    / f"{APP_NAME}.exe"
)

INSTALLER_SCRIPT = (
    PROJECT_ROOT
    / "installer"
    / "windows"
    / "AntiArchiveScanner.iss"
)

RELEASE_DIR = (
    PROJECT_ROOT
    / "release"
    / "windows"
)

INSTALLER_PATH = (
    RELEASE_DIR
    / f"{APP_NAME}-Setup.exe"
)


def validate_platform() -> None:
    if platform.system() != "Windows":
        raise RuntimeError(
            "Windows-установщик можно собрать только на Windows."
        )


def validate_application_build() -> None:
    if not EXECUTABLE_PATH.exists():
        raise FileNotFoundError(
            "Собранное Windows-приложение не найдено:\n"
            f"{EXECUTABLE_PATH}\n\n"
            "Сначала выполни:\n"
            "python scripts\\build.py"
        )

    if not EXECUTABLE_PATH.is_file():
        raise RuntimeError(
            "Путь приложения не является обычным файлом:\n"
            f"{EXECUTABLE_PATH}"
        )


def validate_installer_script() -> None:
    if not INSTALLER_SCRIPT.exists():
        raise FileNotFoundError(
            "Сценарий Inno Setup не найден:\n"
            f"{INSTALLER_SCRIPT}"
        )


def find_inno_setup_compiler() -> Path:
    environment_path = os.environ.get(
        "INNO_SETUP_COMPILER"
    )

    if environment_path:
        candidate = Path(environment_path)

        if candidate.exists():
            return candidate

    common_paths = [
        Path(
            r"C:\Program Files (x86)"
        )
        / "Inno Setup 6"
        / "ISCC.exe",
        Path(
            r"C:\Program Files"
        )
        / "Inno Setup 6"
        / "ISCC.exe",
    ]

    for candidate in common_paths:
        if candidate.exists():
            return candidate

    compiler_from_path = shutil.which(
        "ISCC.exe"
    )

    if compiler_from_path:
        return Path(
            compiler_from_path
        )

    raise FileNotFoundError(
        "Компилятор Inno Setup не найден.\n\n"
        "Установи Inno Setup 6 или укажи путь через "
        "переменную окружения INNO_SETUP_COMPILER."
    )


def prepare_release_directory() -> None:
    RELEASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    if INSTALLER_PATH.exists():
        INSTALLER_PATH.unlink()


def run_installer_build(
    compiler_path: Path,
) -> None:
    command = [
        str(compiler_path),
        str(INSTALLER_SCRIPT),
    ]

    print()
    print("=" * 60)
    print("Создание Windows-установщика")
    print("=" * 60)
    print(" ".join(command))

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
        creationflags=getattr(
            subprocess,
            "CREATE_NO_WINDOW",
            0,
        ),
    )

    if result.stdout.strip():
        print(result.stdout.strip())

    if result.returncode != 0:
        error_message = (
            result.stderr.strip()
            or result.stdout.strip()
            or "Неизвестная ошибка Inno Setup"
        )

        raise RuntimeError(
            "Не удалось собрать Windows-установщик:\n"
            f"{error_message}"
        )


def verify_installer() -> None:
    if not INSTALLER_PATH.exists():
        raise FileNotFoundError(
            "Установщик не был создан:\n"
            f"{INSTALLER_PATH}"
        )

    if not INSTALLER_PATH.is_file():
        raise RuntimeError(
            "Путь установщика не является файлом:\n"
            f"{INSTALLER_PATH}"
        )

    if INSTALLER_PATH.stat().st_size == 0:
        raise RuntimeError(
            "Созданный установщик пуст."
        )


def create_windows_installer() -> Path:
    validate_platform()
    validate_application_build()
    validate_installer_script()

    compiler_path = (
        find_inno_setup_compiler()
    )

    prepare_release_directory()

    run_installer_build(
        compiler_path
    )

    verify_installer()

    return INSTALLER_PATH


def main() -> int:
    try:
        installer_path = (
            create_windows_installer()
        )

    except (
        RuntimeError,
        FileNotFoundError,
        OSError,
    ) as error:
        print()
        print("=" * 60)
        print("Создание установщика завершилось ошибкой")
        print("=" * 60)
        print(error)

        return 1

    print()
    print("=" * 60)
    print("Windows-установщик успешно создан")
    print("=" * 60)
    print(installer_path)

    size_mb = (
        installer_path.stat().st_size
        / 1024
        / 1024
    )

    print(
        f"Размер: {size_mb:.2f} MB"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())