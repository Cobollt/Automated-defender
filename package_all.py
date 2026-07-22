#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent

APP_NAME = "AntiArchiveScanner"
UPDATER_NAME = "AntiArchiveScannerUpdater"
APP_VERSION = "1.0.0"

APP_ENTRY_POINT = PROJECT_ROOT / "app.py"
UPDATER_ENTRY_POINT = PROJECT_ROOT / "updater.py"

REQUIREMENTS_PATH = PROJECT_ROOT / "requirements.txt"
README_PATH = PROJECT_ROOT / "README.md"

BUILD_DIR = PROJECT_ROOT / "build"
DIST_DIR = PROJECT_ROOT / "dist"
RELEASE_DIR = PROJECT_ROOT / "release"

WINDOWS_RELEASE_DIR = RELEASE_DIR / "windows"
MACOS_RELEASE_DIR = RELEASE_DIR / "macos"

WINDOWS_ICON = (
    PROJECT_ROOT
    / "resources"
    / "icon.ico"
)

WINDOWS_UPDATER_ICON = (
    PROJECT_ROOT
    / "resources"
    / "update.ico"
)

MACOS_ICON = (
    PROJECT_ROOT
    / "resources"
    / "icon.icns"
)

MACOS_UPDATER_ICON = (
    PROJECT_ROOT
    / "resources"
    / "update.icns"
)

DMG_BACKGROUND = (
    PROJECT_ROOT
    / "resources"
    / "dmg-background.png"
)

INNO_SCRIPT = (
    PROJECT_ROOT
    / "installer"
    / "windows"
    / "AntiArchiveScanner.iss"
)

WINDOWS_DOWNLOAD_URL = (
    "https://example.com/releases/"
    "AntiArchiveScanner-Setup.exe"
)

MACOS_DOWNLOAD_URL = (
    "https://example.com/releases/"
    "AntiArchiveScanner.dmg"
)

HASH_BUFFER_SIZE = 1024 * 1024


class PackagingError(RuntimeError):
    """Ошибка подготовки релиза."""


def print_header(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def run_command(
    command: list[str],
    description: str,
    *,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    print_header(description)
    print(" ".join(command))
    print()

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        check=False,
        text=True,
        capture_output=capture_output,
    )

    if capture_output:
        if result.stdout:
            print(result.stdout.strip())

        if result.stderr:
            print(result.stderr.strip())

    if result.returncode != 0:
        raise PackagingError(
            f"{description} завершено с ошибкой. "
            f"Код возврата: {result.returncode}"
        )

    return result


def detect_platform() -> str:
    system_name = platform.system()

    if system_name == "Darwin":
        return "macos"

    if system_name == "Windows":
        return "windows"

    raise PackagingError(
        "Поддерживаются только Windows и macOS. "
        f"Текущая система: {system_name}"
    )


def validate_project() -> None:
    required_paths = [
        APP_ENTRY_POINT,
        UPDATER_ENTRY_POINT,
    ]

    missing_paths = [
        path
        for path in required_paths
        if not path.exists()
    ]

    if missing_paths:
        formatted_paths = "\n".join(
            str(path)
            for path in missing_paths
        )

        raise PackagingError(
            "Не найдены обязательные файлы:\n"
            f"{formatted_paths}"
        )


def check_python_version() -> None:
    if sys.version_info < (3, 10):
        raise PackagingError(
            "Требуется Python 3.10 или новее. "
            f"Текущая версия: {platform.python_version()}"
        )


def check_virtual_environment() -> None:
    in_virtual_environment = (
        sys.prefix != sys.base_prefix
        or bool(os.environ.get("VIRTUAL_ENV"))
    )

    if not in_virtual_environment:
        print()
        print(
            "Предупреждение: виртуальное окружение "
            "не активировано."
        )
        print(
            "Сборка продолжится с текущим "
            "интерпретатором Python."
        )


def install_dependencies(
    install: bool,
) -> None:
    if not install:
        return

    run_command(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--upgrade",
            "pip",
        ],
        "Обновление pip",
    )

    if REQUIREMENTS_PATH.exists():
        run_command(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "-r",
                str(REQUIREMENTS_PATH),
            ],
            "Установка зависимостей проекта",
        )

    run_command(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "pyinstaller",
            "pytest",
        ],
        "Установка инструментов сборки",
    )


def check_dependencies() -> None:
    run_command(
        [
            sys.executable,
            "-c",
            (
                "import PyInstaller; "
                "import pytest; "
                "import watchdog"
            ),
        ],
        "Проверка зависимостей",
    )


def run_syntax_check() -> None:
    source_names = [
        "app.py",
        "updater.py",
        "config.py",
        "application",
        "domain",
        "infrastructure",
        "platform_services",
        "presentation",
        "utils",
        "tests",
    ]

    source_paths = [
        str(PROJECT_ROOT / name)
        for name in source_names
        if (PROJECT_ROOT / name).exists()
    ]

    run_command(
        [
            sys.executable,
            "-m",
            "compileall",
            "-q",
            *source_paths,
        ],
        "Проверка синтаксиса",
    )


def run_tests() -> None:
    tests_directory = PROJECT_ROOT / "tests"

    if not tests_directory.exists():
        print()
        print(
            "Каталог tests не найден. "
            "Запуск тестов пропущен."
        )
        return

    run_command(
        [
            sys.executable,
            "-m",
            "pytest",
            "-v",
            "--tb=short",
        ],
        "Запуск тестов",
    )


def clean_build_directories() -> None:
    print_header("Очистка предыдущей сборки")

    for directory in (
        BUILD_DIR,
        DIST_DIR,
        RELEASE_DIR,
    ):
        if directory.exists():
            print(f"Удаление: {directory}")
            shutil.rmtree(directory)

    for spec_file in PROJECT_ROOT.glob("*.spec"):
        print(f"Удаление временного spec: {spec_file}")
        spec_file.unlink()

    RELEASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def application_icon(
    target_platform: str,
) -> Path | None:
    if target_platform == "windows":
        return (
            WINDOWS_ICON
            if WINDOWS_ICON.exists()
            else None
        )

    return (
        MACOS_ICON
        if MACOS_ICON.exists()
        else None
    )


def updater_icon(
    target_platform: str,
) -> Path | None:
    if target_platform == "windows":
        if WINDOWS_UPDATER_ICON.exists():
            return WINDOWS_UPDATER_ICON

        return application_icon(target_platform)

    if MACOS_UPDATER_ICON.exists():
        return MACOS_UPDATER_ICON

    return application_icon(target_platform)


def create_pyinstaller_command(
    *,
    name: str,
    entry_point: Path,
    icon_path: Path | None,
    target_platform: str,
    is_updater: bool,
) -> list[str]:
    command = [
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

    hidden_imports = [
        "tkinter",
        "tkinter.messagebox",
    ]

    if not is_updater:
        hidden_imports.extend(
            [
                "watchdog.events",
                "watchdog.observers",
            ]
        )

        if target_platform == "windows":
            hidden_imports.append(
                "watchdog.observers.read_directory_changes"
            )
        else:
            hidden_imports.extend(
                [
                    "watchdog.observers.fsevents",
                    "watchdog.observers.kqueue",
                ]
            )

    for hidden_import in hidden_imports:
        command.extend(
            [
                "--hidden-import",
                hidden_import,
            ]
        )

    if icon_path is not None:
        command.extend(
            [
                "--icon",
                str(icon_path),
            ]
        )

    command.append(
        str(entry_point)
    )

    return command


def build_binaries(
    target_platform: str,
) -> None:
    app_command = create_pyinstaller_command(
        name=APP_NAME,
        entry_point=APP_ENTRY_POINT,
        icon_path=application_icon(
            target_platform
        ),
        target_platform=target_platform,
        is_updater=False,
    )

    run_command(
        app_command,
        "Сборка основной программы",
    )

    updater_command = create_pyinstaller_command(
        name=UPDATER_NAME,
        entry_point=UPDATER_ENTRY_POINT,
        icon_path=updater_icon(
            target_platform
        ),
        target_platform=target_platform,
        is_updater=True,
    )

    run_command(
        updater_command,
        "Сборка программы обновления",
    )


def validate_binaries(
    target_platform: str,
) -> None:
    if target_platform == "windows":
        expected_paths = [
            (
                DIST_DIR
                / APP_NAME
                / f"{APP_NAME}.exe"
            ),
            (
                DIST_DIR
                / UPDATER_NAME
                / f"{UPDATER_NAME}.exe"
            ),
        ]
    else:
        expected_paths = [
            (
                DIST_DIR
                / f"{APP_NAME}.app"
                / "Contents"
                / "MacOS"
                / APP_NAME
            ),
            (
                DIST_DIR
                / f"{UPDATER_NAME}.app"
                / "Contents"
                / "MacOS"
                / UPDATER_NAME
            ),
        ]

    for path in expected_paths:
        if not path.is_file():
            raise PackagingError(
                "Не найден собранный файл:\n"
                f"{path}"
            )

        if path.stat().st_size == 0:
            raise PackagingError(
                "Собранный файл пуст:\n"
                f"{path}"
            )


def find_inno_setup_compiler() -> Path:
    environment_path = os.environ.get(
        "INNO_SETUP_COMPILER"
    )

    candidates: list[Path] = []

    if environment_path:
        candidates.append(
            Path(environment_path)
        )

    candidates.extend(
        [
            Path(
                r"C:\Program Files (x86)"
                r"\Inno Setup 6\ISCC.exe"
            ),
            Path(
                r"C:\Program Files"
                r"\Inno Setup 6\ISCC.exe"
            ),
        ]
    )

    compiler_from_path = shutil.which("ISCC")

    if compiler_from_path:
        candidates.append(
            Path(compiler_from_path)
        )

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    raise PackagingError(
        "Не найден компилятор Inno Setup 6.\n"
        "Установите Inno Setup или задайте переменную:\n"
        "INNO_SETUP_COMPILER="
        r"C:\...\ISCC.exe"
    )


def build_windows_installer() -> Path:
    if not INNO_SCRIPT.is_file():
        raise PackagingError(
            "Не найден сценарий Inno Setup:\n"
            f"{INNO_SCRIPT}"
        )

    WINDOWS_RELEASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    compiler_path = find_inno_setup_compiler()

    run_command(
        [
            str(compiler_path),
            f"/DAppVersion={APP_VERSION}",
            f"/DProjectRoot={PROJECT_ROOT}",
            f"/DOutputDir={WINDOWS_RELEASE_DIR}",
            str(INNO_SCRIPT),
        ],
        "Создание Windows-установщика",
    )

    installer_path = (
        WINDOWS_RELEASE_DIR
        / f"{APP_NAME}-Setup.exe"
    )

    if not installer_path.is_file():
        matching_files = list(
            WINDOWS_RELEASE_DIR.glob(
                "*.exe"
            )
        )

        if len(matching_files) == 1:
            generated_path = matching_files[0]
            generated_path.replace(
                installer_path
            )

    if not installer_path.is_file():
        raise PackagingError(
            "Inno Setup завершил работу, "
            "но установщик не найден:\n"
            f"{installer_path}"
        )

    return installer_path


def copy_macos_bundle(
    source: Path,
    destination: Path,
) -> None:
    shutil.copytree(
        source,
        destination,
        symlinks=True,
    )


def create_macos_launcher(
    staging_directory: Path,
) -> None:
    launcher_path = (
        staging_directory
        / "Запустить AntiArchiveScanner.command"
    )

    launcher_content = f"""#!/bin/bash

INSTALLED_APP="/Applications/{APP_NAME}.app"

if [ -d "$INSTALLED_APP" ]; then
    open "$INSTALLED_APP"
    exit 0
fi

CURRENT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLED_APP="$CURRENT_DIR/{APP_NAME}.app"

if [ -d "$BUNDLED_APP" ]; then
    open "$BUNDLED_APP"
    exit 0
fi

osascript -e 'display dialog "Перетащите AntiArchiveScanner.app в папку Applications." buttons {{"OK"}} default button "OK" with icon caution'
exit 1
"""

    launcher_path.write_text(
        launcher_content,
        encoding="utf-8",
    )
    launcher_path.chmod(0o755)


def create_macos_update_launcher(
    staging_directory: Path,
) -> None:
    launcher_path = (
        staging_directory
        / "Проверить обновления.command"
    )

    launcher_content = f"""#!/bin/bash

INSTALLED_UPDATER="/Applications/{UPDATER_NAME}.app"

if [ -d "$INSTALLED_UPDATER" ]; then
    open "$INSTALLED_UPDATER"
    exit 0
fi

CURRENT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLED_UPDATER="$CURRENT_DIR/{UPDATER_NAME}.app"

if [ -d "$BUNDLED_UPDATER" ]; then
    open "$BUNDLED_UPDATER"
    exit 0
fi

osascript -e 'display dialog "Программа обновления не найдена." buttons {{"OK"}} default button "OK" with icon caution'
exit 1
"""

    launcher_path.write_text(
        launcher_content,
        encoding="utf-8",
    )
    launcher_path.chmod(0o755)


def create_macos_install_text(
    staging_directory: Path,
) -> None:
    install_text = (
        "Установка AntiArchiveScanner\n"
        "=============================\n\n"
        "1. Перетащите AntiArchiveScanner.app "
        "в папку Applications.\n"
        "2. Перетащите AntiArchiveScannerUpdater.app "
        "в папку Applications.\n"
        "3. Запустите AntiArchiveScanner "
        "из папки Applications.\n"
        "4. Для проверки обновлений используйте "
        "AntiArchiveScannerUpdater.\n"
    )

    (
        staging_directory
        / "INSTALL.txt"
    ).write_text(
        install_text,
        encoding="utf-8",
    )


def directory_size(
    directory: Path,
) -> int:
    total_size = 0

    for path in directory.rglob("*"):
        if (
            path.is_file()
            and not path.is_symlink()
        ):
            total_size += path.stat().st_size

    return total_size


def build_macos_dmg() -> Path:
    MACOS_RELEASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    application_bundle = (
        DIST_DIR
        / f"{APP_NAME}.app"
    )

    updater_bundle = (
        DIST_DIR
        / f"{UPDATER_NAME}.app"
    )

    if not application_bundle.is_dir():
        raise PackagingError(
            "Не найден основной .app:\n"
            f"{application_bundle}"
        )

    if not updater_bundle.is_dir():
        raise PackagingError(
            "Не найден updater .app:\n"
            f"{updater_bundle}"
        )

    dmg_path = (
        MACOS_RELEASE_DIR
        / f"{APP_NAME}.dmg"
    )

    if dmg_path.exists():
        dmg_path.unlink()

    with tempfile.TemporaryDirectory(
        prefix="anti_archive_scanner_dmg_"
    ) as temporary_directory:
        staging_directory = (
            Path(temporary_directory)
            / APP_NAME
        )

        staging_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        copy_macos_bundle(
            application_bundle,
            (
                staging_directory
                / application_bundle.name
            ),
        )

        copy_macos_bundle(
            updater_bundle,
            (
                staging_directory
                / updater_bundle.name
            ),
        )

        (
            staging_directory
            / "Applications"
        ).symlink_to(
            "/Applications",
            target_is_directory=True,
        )

        create_macos_launcher(
            staging_directory
        )
        create_macos_update_launcher(
            staging_directory
        )
        create_macos_install_text(
            staging_directory
        )

        if README_PATH.is_file():
            shutil.copy2(
                README_PATH,
                staging_directory / "README.md",
            )

        if DMG_BACKGROUND.is_file():
            background_directory = (
                staging_directory
                / ".background"
            )
            background_directory.mkdir()

            shutil.copy2(
                DMG_BACKGROUND,
                (
                    background_directory
                    / DMG_BACKGROUND.name
                ),
            )

        content_size = directory_size(
            staging_directory
        )

        size_megabytes = max(
            150,
            int(
                content_size
                / 1024
                / 1024
                * 1.5
            )
            + 50,
        )

        run_command(
            [
                "hdiutil",
                "create",
                "-volname",
                APP_NAME,
                "-srcfolder",
                str(staging_directory),
                "-ov",
                "-format",
                "UDZO",
                "-imagekey",
                "zlib-level=9",
                "-size",
                f"{size_megabytes}m",
                str(dmg_path),
            ],
            "Создание macOS DMG",
        )

    run_command(
        [
            "hdiutil",
            "verify",
            str(dmg_path),
        ],
        "Проверка macOS DMG",
    )

    if not dmg_path.is_file():
        raise PackagingError(
            "DMG не создан:\n"
            f"{dmg_path}"
        )

    return dmg_path


def create_portable_archive(
    target_platform: str,
) -> Path:
    if target_platform == "windows":
        release_directory = (
            WINDOWS_RELEASE_DIR
        )

        source_items = [
            DIST_DIR / APP_NAME,
            DIST_DIR / UPDATER_NAME,
        ]
    else:
        release_directory = (
            MACOS_RELEASE_DIR
        )

        source_items = [
            DIST_DIR / f"{APP_NAME}.app",
            DIST_DIR / f"{UPDATER_NAME}.app",
        ]

    release_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    portable_directory = (
        release_directory
        / f"{APP_NAME}-portable"
    )

    if portable_directory.exists():
        shutil.rmtree(
            portable_directory
        )

    portable_directory.mkdir(
        parents=True
    )

    for source_item in source_items:
        if not source_item.exists():
            raise PackagingError(
                "Не найден элемент portable-сборки:\n"
                f"{source_item}"
            )

        destination = (
            portable_directory
            / source_item.name
        )

        if source_item.is_dir():
            shutil.copytree(
                source_item,
                destination,
                symlinks=True,
            )
        else:
            shutil.copy2(
                source_item,
                destination,
            )

    if README_PATH.is_file():
        shutil.copy2(
            README_PATH,
            portable_directory / "README.md",
        )

    archive_base = (
        release_directory
        / f"{APP_NAME}-portable"
    )

    archive_path = Path(
        shutil.make_archive(
            base_name=str(archive_base),
            format="zip",
            root_dir=portable_directory.parent,
            base_dir=portable_directory.name,
        )
    )

    shutil.rmtree(
        portable_directory
    )

    return archive_path


def calculate_sha256(
    file_path: Path,
) -> str:
    digest = hashlib.sha256()

    with file_path.open("rb") as source_file:
        while True:
            chunk = source_file.read(
                HASH_BUFFER_SIZE
            )

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def create_platform_manifest(
    target_platform: str,
    installer_path: Path,
) -> Path:
    release_directory = (
        WINDOWS_RELEASE_DIR
        if target_platform == "windows"
        else MACOS_RELEASE_DIR
    )

    manifest: dict[str, Any] = {
        "version": APP_VERSION,
        "published_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "windows": {
            "url": WINDOWS_DOWNLOAD_URL,
            "sha256": "",
        },
        "macos": {
            "url": MACOS_DOWNLOAD_URL,
            "sha256": "",
        },
    }

    installer_hash = calculate_sha256(
        installer_path
    )

    manifest[target_platform]["sha256"] = (
        installer_hash
    )

    manifest_path = (
        release_directory
        / "update-manifest.json"
    )

    manifest_path.write_text(
        json.dumps(
            manifest,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    return manifest_path


def create_release_information(
    target_platform: str,
    installer_path: Path,
    portable_path: Path,
) -> Path:
    release_directory = (
        WINDOWS_RELEASE_DIR
        if target_platform == "windows"
        else MACOS_RELEASE_DIR
    )

    information_path = (
        release_directory
        / "RELEASE_INFO.txt"
    )

    information = (
        f"Application: {APP_NAME}\n"
        f"Version: {APP_VERSION}\n"
        f"Platform: {target_platform}\n"
        f"Architecture: {platform.machine()}\n"
        f"Python: {platform.python_version()}\n"
        f"Installer: {installer_path.name}\n"
        f"Installer SHA-256: "
        f"{calculate_sha256(installer_path)}\n"
        f"Portable: {portable_path.name}\n"
        f"Portable SHA-256: "
        f"{calculate_sha256(portable_path)}\n"
        f"Created: "
        f"{datetime.now(timezone.utc).isoformat()}\n"
    )

    information_path.write_text(
        information,
        encoding="utf-8",
    )

    return information_path


def verify_release_files(
    files: list[Path],
) -> None:
    for file_path in files:
        if not file_path.is_file():
            raise PackagingError(
                "Файл релиза не найден:\n"
                f"{file_path}"
            )

        if file_path.stat().st_size == 0:
            raise PackagingError(
                "Файл релиза пуст:\n"
                f"{file_path}"
            )


def print_summary(
    target_platform: str,
    installer_path: Path,
    portable_path: Path,
    manifest_path: Path,
    information_path: Path,
) -> None:
    print_header(
        "Упаковка завершена успешно"
    )

    print(
        f"Платформа: {target_platform}"
    )
    print(
        f"Версия: {APP_VERSION}"
    )
    print()

    print("Установщик:")
    print(installer_path)
    print()

    print("Portable ZIP:")
    print(portable_path)
    print()

    print("Манифест обновления:")
    print(manifest_path)
    print()

    print("Информация о релизе:")
    print(information_path)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Полная сборка AntiArchiveScanner "
            "для текущей операционной системы."
        )
    )

    parser.add_argument(
        "--install-dependencies",
        action="store_true",
        help=(
            "Обновить pip и установить "
            "зависимости перед сборкой."
        ),
    )

    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Не запускать pytest.",
    )

    parser.add_argument(
        "--skip-clean",
        action="store_true",
        help=(
            "Не удалять предыдущие "
            "build, dist и release."
        ),
    )

    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()

    try:
        print_header(
            "AntiArchiveScanner Packaging"
        )

        target_platform = detect_platform()

        print(
            f"Операционная система: "
            f"{platform.system()}"
        )
        print(
            f"Целевая платформа: "
            f"{target_platform}"
        )
        print(
            f"Архитектура: "
            f"{platform.machine()}"
        )
        print(
            f"Python: "
            f"{platform.python_version()}"
        )

        validate_project()
        check_python_version()
        check_virtual_environment()

        install_dependencies(
            arguments.install_dependencies
        )

        check_dependencies()
        run_syntax_check()

        if not arguments.skip_tests:
            run_tests()

        if not arguments.skip_clean:
            clean_build_directories()
        else:
            RELEASE_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

        build_binaries(
            target_platform
        )

        validate_binaries(
            target_platform
        )

        if target_platform == "windows":
            installer_path = (
                build_windows_installer()
            )
        else:
            installer_path = (
                build_macos_dmg()
            )

        portable_path = (
            create_portable_archive(
                target_platform
            )
        )

        manifest_path = (
            create_platform_manifest(
                target_platform,
                installer_path,
            )
        )

        information_path = (
            create_release_information(
                target_platform,
                installer_path,
                portable_path,
            )
        )

        verify_release_files(
            [
                installer_path,
                portable_path,
                manifest_path,
                information_path,
            ]
        )

        print_summary(
            target_platform,
            installer_path,
            portable_path,
            manifest_path,
            information_path,
        )

        return 0

    except (
        PackagingError,
        FileNotFoundError,
        OSError,
    ) as error:
        print_header(
            "Упаковка завершилась ошибкой"
        )
        print(error)

        return 1

    except KeyboardInterrupt:
        print()
        print(
            "Упаковка остановлена пользователем."
        )

        return 130


if __name__ == "__main__":
    raise SystemExit(main())