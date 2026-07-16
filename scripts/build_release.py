#!/usr/bin/env python3

import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

APP_NAME = "AntiArchiveScanner"
APP_VERSION = "1.0.0"

BUILD_DIR = PROJECT_ROOT / "build"
DIST_DIR = PROJECT_ROOT / "dist"
RELEASE_DIR = PROJECT_ROOT / "release"

WINDOWS_RELEASE_DIR = RELEASE_DIR / "windows"
MACOS_RELEASE_DIR = RELEASE_DIR / "macos"

BUFFER_SIZE = 1024 * 1024

# Перед публикацией замени на адрес своего сервера
# или GitHub Releases.
WINDOWS_DOWNLOAD_URL = (
    "https://github.com/Cobollt/Automated-defender.git"
    "AntiArchiveScanner-Setup.exe"
)

MACOS_DOWNLOAD_URL = (
    "https://github.com/Cobollt/Automated-defender.git"
    "AntiArchiveScanner.dmg"
)


def run_command(
    command: list[str],
    description: str,
) -> None:
    print()
    print("=" * 70)
    print(description)
    print("=" * 70)
    print(" ".join(command))

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{description} завершено с ошибкой "
            f"({result.returncode})"
        )


def check_platform() -> str:
    system_name = platform.system()

    if system_name not in {
        "Windows",
        "Darwin",
    }:
        raise RuntimeError(
            "Упаковка поддерживается только "
            "на Windows и macOS."
        )

    return system_name


def check_required_files() -> None:
    required_files = [
        PROJECT_ROOT / "app.py",
        PROJECT_ROOT / "updater.py",
        PROJECT_ROOT / "requirements.txt",
        PROJECT_ROOT / "scripts" / "build.py",
    ]

    for file_path in required_files:
        if not file_path.exists():
            raise FileNotFoundError(
                f"Не найден обязательный файл: "
                f"{file_path}"
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


def run_compile_check() -> None:
    source_paths = [
        "app.py",
        "updater.py",
        "config.py",
        "application",
        "domain",
        "infrastructure",
        "platform_services",
        "presentation",
        "utils",
        "scripts",
        "tests",
    ]

    existing_paths = [
        str(PROJECT_ROOT / path)
        for path in source_paths
        if (PROJECT_ROOT / path).exists()
    ]

    run_command(
        [
            sys.executable,
            "-m",
            "compileall",
            "-q",
            *existing_paths,
        ],
        "Проверка синтаксиса",
    )


def run_tests() -> None:
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


def clean_old_builds() -> None:
    for directory in (
        BUILD_DIR,
        DIST_DIR,
        RELEASE_DIR,
    ):
        if directory.exists():
            shutil.rmtree(directory)

    RELEASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def build_binaries() -> None:
    run_command(
        [
            sys.executable,
            str(
                PROJECT_ROOT
                / "scripts"
                / "build.py"
            ),
        ],
        "Сборка приложения и updater",
    )


def build_installer(
    system_name: str,
) -> Path:
    if system_name == "Darwin":
        run_command(
            [
                sys.executable,
                str(
                    PROJECT_ROOT
                    / "scripts"
                    / "create_macos_dmg.py"
                ),
            ],
            "Создание macOS DMG",
        )

        installer_path = (
            MACOS_RELEASE_DIR
            / f"{APP_NAME}.dmg"
        )

    else:
        run_command(
            [
                sys.executable,
                str(
                    PROJECT_ROOT
                    / "scripts"
                    / "create_windows_installer.py"
                ),
            ],
            "Создание Windows Setup",
        )

        installer_path = (
            WINDOWS_RELEASE_DIR
            / f"{APP_NAME}-Setup.exe"
        )

    if not installer_path.exists():
        raise FileNotFoundError(
            "Итоговый установщик не найден: "
            f"{installer_path}"
        )

    return installer_path


def calculate_sha256(
    file_path: Path,
) -> str:
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        while True:
            chunk = file.read(BUFFER_SIZE)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def create_portable_archive(
    system_name: str,
) -> Path:
    if system_name == "Darwin":
        source_items = [
            DIST_DIR / f"{APP_NAME}.app",
            DIST_DIR / "AntiArchiveScannerUpdater.app",
        ]

        target_dir = (
            MACOS_RELEASE_DIR
            / f"{APP_NAME}-portable"
        )

        archive_base = (
            MACOS_RELEASE_DIR
            / f"{APP_NAME}-portable"
        )

    else:
        source_items = [
            DIST_DIR / APP_NAME,
            DIST_DIR / "AntiArchiveScannerUpdater",
        ]

        target_dir = (
            WINDOWS_RELEASE_DIR
            / f"{APP_NAME}-portable"
        )

        archive_base = (
            WINDOWS_RELEASE_DIR
            / f"{APP_NAME}-portable"
        )

    if target_dir.exists():
        shutil.rmtree(target_dir)

    target_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    for source_item in source_items:
        if not source_item.exists():
            raise FileNotFoundError(
                f"Не найден файл portable-сборки: "
                f"{source_item}"
            )

        destination = target_dir / source_item.name

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

    readme_path = PROJECT_ROOT / "README.md"

    if readme_path.exists():
        shutil.copy2(
            readme_path,
            target_dir / "README.md",
        )

    archive_path = Path(
        shutil.make_archive(
            base_name=str(archive_base),
            format="zip",
            root_dir=target_dir.parent,
            base_dir=target_dir.name,
        )
    )

    shutil.rmtree(target_dir)

    return archive_path


def create_update_manifest(
    system_name: str,
    installer_path: Path,
) -> Path:
    manifest = {
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

    if system_name == "Windows":
        manifest["windows"]["sha256"] = (
            installer_hash
        )
    else:
        manifest["macos"]["sha256"] = (
            installer_hash
        )

    manifest_path = (
        installer_path.parent
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


def create_release_info(
    system_name: str,
    installer_path: Path,
    portable_path: Path,
) -> Path:
    info_path = (
        installer_path.parent
        / "RELEASE_INFO.txt"
    )

    content = (
        f"Application: {APP_NAME}\n"
        f"Version: {APP_VERSION}\n"
        f"Platform: {system_name}\n"
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

    info_path.write_text(
        content,
        encoding="utf-8",
    )

    return info_path


def verify_release_files(
    files: list[Path],
) -> None:
    for file_path in files:
        if not file_path.exists():
            raise FileNotFoundError(
                f"Файл релиза не создан: "
                f"{file_path}"
            )

        if not file_path.is_file():
            raise RuntimeError(
                f"Путь релиза не является файлом: "
                f"{file_path}"
            )

        if file_path.stat().st_size == 0:
            raise RuntimeError(
                f"Файл релиза пуст: "
                f"{file_path}"
            )


def print_summary(
    system_name: str,
    installer_path: Path,
    portable_path: Path,
    manifest_path: Path,
    info_path: Path,
) -> None:
    print()
    print("=" * 70)
    print("Упаковка завершена успешно")
    print("=" * 70)

    print("Платформа:", system_name)
    print("Версия:", APP_VERSION)

    print()
    print("Установщик:")
    print(installer_path)

    print()
    print("Portable ZIP:")
    print(portable_path)

    print()
    print("Update manifest:")
    print(manifest_path)

    print()
    print("Release information:")
    print(info_path)


def main() -> int:
    try:
        system_name = check_platform()

        check_required_files()
        check_dependencies()
        run_compile_check()
        run_tests()

        clean_old_builds()
        build_binaries()

        installer_path = build_installer(
            system_name
        )

        portable_path = create_portable_archive(
            system_name
        )

        manifest_path = create_update_manifest(
            system_name=system_name,
            installer_path=installer_path,
        )

        info_path = create_release_info(
            system_name=system_name,
            installer_path=installer_path,
            portable_path=portable_path,
        )

        verify_release_files(
            [
                installer_path,
                portable_path,
                manifest_path,
                info_path,
            ]
        )

        print_summary(
            system_name=system_name,
            installer_path=installer_path,
            portable_path=portable_path,
            manifest_path=manifest_path,
            info_path=info_path,
        )

    except (
        RuntimeError,
        FileNotFoundError,
        OSError,
    ) as error:
        print()
        print("=" * 70)
        print("Упаковка завершилась ошибкой")
        print("=" * 70)
        print(error)

        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())