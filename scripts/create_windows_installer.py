#!/usr/bin/env python3

import argparse
import os
import platform
import shutil
import subprocess
from pathlib import Path

from packaging.version import (
    InvalidVersion,
    Version,
)


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

DIST_DIR = (
    PROJECT_ROOT
    / "dist"
)

APP_DIST_DIR = (
    DIST_DIR
    / APP_NAME
)

UPDATER_DIST_DIR = (
    DIST_DIR
    / UPDATER_NAME
)

APP_EXECUTABLE = (
    APP_DIST_DIR
    / f"{APP_NAME}.exe"
)

UPDATER_EXECUTABLE = (
    UPDATER_DIST_DIR
    / f"{UPDATER_NAME}.exe"
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

WINDOWS_ICON = (
    PROJECT_ROOT
    / "resources"
    / "icon.ico"
)


class InstallerBuildError(
    RuntimeError
):
    pass


def parse_arguments(
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create Windows installer "
            "for AntiArchiveScanner."
        )
    )

    parser.add_argument(
        "--version",
        default="1.0.0",
        help=(
            "Application version, "
            "for example 1.0.1."
        ),
    )

    return parser.parse_args()


def validate_version(
    version: str,
) -> str:
    normalized = (
        version
        .strip()
        .lstrip("v")
    )

    if not normalized:
        raise InstallerBuildError(
            "Версия приложения "
            "не может быть пустой."
        )

    try:
        parsed = Version(
            normalized
        )

    except InvalidVersion as error:
        raise InstallerBuildError(
            "Некорректная версия: "
            f"{version}"
        ) from error

    return str(
        parsed
    )


def validate_platform(
) -> None:
    if (
        platform.system()
        != "Windows"
    ):
        raise InstallerBuildError(
            "Windows-установщик "
            "можно собрать только "
            "на Windows."
        )


def validate_application_build(
) -> None:
    validate_directory(
        APP_DIST_DIR,
        (
            "Каталог основной "
            "программы"
        ),
    )

    validate_file(
        APP_EXECUTABLE,
        (
            "Основной executable"
        ),
    )

    validate_directory(
        UPDATER_DIST_DIR,
        "Каталог updater",
    )

    validate_file(
        UPDATER_EXECUTABLE,
        "Updater executable",
    )

    main_internal = (
        APP_DIST_DIR
        / "_internal"
    )

    updater_internal = (
        UPDATER_DIST_DIR
        / "_internal"
    )

    if not main_internal.exists():
        print(
            "Предупреждение: "
            "у основного приложения "
            "нет каталога _internal."
        )

    if (
        not updater_internal.exists()
    ):
        print(
            "Предупреждение: "
            "у updater нет "
            "каталога _internal."
        )


def validate_installer_script(
) -> None:
    validate_file(
        INSTALLER_SCRIPT,
        (
            "Inno Setup script"
        ),
    )


def validate_file(
    path: Path,
    description: str,
) -> None:
    if not path.exists():
        raise FileNotFoundError(
            f"{description} "
            "не найден:\n"
            f"{path}"
        )

    if not path.is_file():
        raise InstallerBuildError(
            f"{description} "
            "не является файлом:\n"
            f"{path}"
        )

    if (
        path.stat().st_size
        <= 0
    ):
        raise InstallerBuildError(
            f"{description} "
            "пуст:\n"
            f"{path}"
        )


def validate_directory(
    path: Path,
    description: str,
) -> None:
    if not path.exists():
        raise FileNotFoundError(
            f"{description} "
            "не найден:\n"
            f"{path}"
        )

    if not path.is_dir():
        raise InstallerBuildError(
            f"{description} "
            "не является каталогом:\n"
            f"{path}"
        )


def find_inno_setup_compiler(
) -> Path:
    environment_path = (
        os.environ.get(
            "INNO_SETUP_COMPILER"
        )
    )

    if environment_path:
        candidate = Path(
            environment_path
        )

        if (
            candidate.exists()
            and candidate.is_file()
        ):
            return candidate

    common_paths = (
        (
            Path(
                r"C:\Program Files (x86)"
            )
            / "Inno Setup 6"
            / "ISCC.exe"
        ),
        (
            Path(
                r"C:\Program Files"
            )
            / "Inno Setup 6"
            / "ISCC.exe"
        ),
    )

    for candidate in (
        common_paths
    ):
        if (
            candidate.exists()
            and candidate.is_file()
        ):
            return candidate

    compiler_from_path = (
        shutil.which(
            "ISCC.exe"
        )
        or shutil.which(
            "ISCC"
        )
    )

    if compiler_from_path:
        return Path(
            compiler_from_path
        )

    raise FileNotFoundError(
        "Компилятор Inno Setup "
        "не найден.\n\n"
        "Установи Inno Setup 6 "
        "или укажи путь через "
        "переменную окружения "
        "INNO_SETUP_COMPILER."
    )


def prepare_release_directory(
) -> None:
    RELEASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    INSTALLER_PATH.unlink(
        missing_ok=True
    )

    temporary_files = (
        RELEASE_DIR.glob(
            "*.tmp"
        )
    )

    for temporary_file in (
        temporary_files
    ):
        temporary_file.unlink(
            missing_ok=True
        )


def build_compiler_command(
    compiler_path: Path,
    version: str,
) -> list[str]:
    command = [
        str(
            compiler_path
        ),

        (
            "/DAppVersion="
            f"{version}"
        ),
    ]

    if WINDOWS_ICON.exists():
        command.append(
            (
                "/DSetupIconFile="
                f"{WINDOWS_ICON}"
            )
        )

    command.append(
        str(
            INSTALLER_SCRIPT
        )
    )

    return command


def run_installer_build(
    compiler_path: Path,
    version: str,
) -> None:
    command = (
        build_compiler_command(
            compiler_path=(
                compiler_path
            ),
            version=version,
        )
    )

    print()
    print(
        "=" * 72
    )

    print(
        "Создание "
        "Windows-установщика"
    )

    print(
        "=" * 72
    )

    print(
        "Версия:",
        version,
    )

    print()

    print(
        " ".join(
            command
        )
    )

    print()

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
        creationflags=(
            getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0,
            )
        ),
    )

    if (
        result.stdout
        and result.stdout.strip()
    ):
        print(
            result.stdout.strip()
        )

    if (
        result.stderr
        and result.stderr.strip()
    ):
        print(
            result.stderr.strip()
        )

    if (
        result.returncode
        != 0
    ):
        error_message = (
            result.stderr.strip()
            or result.stdout.strip()
            or (
                "Неизвестная ошибка "
                "Inno Setup."
            )
        )

        raise InstallerBuildError(
            "Не удалось собрать "
            "Windows-установщик:\n"
            f"{error_message}"
        )


def verify_installer(
) -> None:
    validate_file(
        INSTALLER_PATH,
        (
            "Windows installer"
        ),
    )


def create_windows_installer(
    version: str,
) -> Path:
    validate_platform()

    normalized_version = (
        validate_version(
            version
        )
    )

    validate_application_build()

    validate_installer_script()

    compiler_path = (
        find_inno_setup_compiler()
    )

    prepare_release_directory()

    run_installer_build(
        compiler_path=(
            compiler_path
        ),
        version=(
            normalized_version
        ),
    )

    verify_installer()

    return INSTALLER_PATH


def main(
) -> int:
    arguments = (
        parse_arguments()
    )

    try:
        version = (
            validate_version(
                arguments.version
            )
        )

        installer_path = (
            create_windows_installer(
                version
            )
        )

    except (
        InstallerBuildError,
        RuntimeError,
        FileNotFoundError,
        OSError,
    ) as error:
        print()
        print(
            "=" * 72
        )

        print(
            "Создание установщика "
            "завершилось ошибкой"
        )

        print(
            "=" * 72
        )

        print(
            error
        )

        return 1

    print()
    print(
        "=" * 72
    )

    print(
        "Windows-установщик "
        "успешно создан"
    )

    print(
        "=" * 72
    )

    print(
        "Версия:",
        version,
    )

    print(
        "Файл:",
        installer_path,
    )

    size_mb = (
        installer_path
        .stat()
        .st_size
        / 1024
        / 1024
    )

    print(
        "Размер:",
        f"{size_mb:.2f} MB",
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )