#!/usr/bin/env python3

import platform
import shutil
import subprocess
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

APP_NAME = "AntiArchiveScanner"
UPDATER_NAME = "AntiArchiveScannerUpdater"

DIST_DIR = PROJECT_ROOT / "dist"
RELEASE_DIR = PROJECT_ROOT / "release" / "macos"

APPLICATION_PATH = DIST_DIR / f"{APP_NAME}.app"
UPDATER_PATH = DIST_DIR / f"{UPDATER_NAME}.app"

DMG_PATH = RELEASE_DIR / f"{APP_NAME}.dmg"
VOLUME_NAME = APP_NAME


def run_command(
    command: list[str],
    description: str,
) -> None:
    print()
    print("=" * 60)
    print(description)
    print("=" * 60)
    print(" ".join(command))

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.stdout.strip():
        print(result.stdout.strip())

    if result.returncode != 0:
        error_message = (
            result.stderr.strip()
            or result.stdout.strip()
            or "Неизвестная ошибка"
        )

        raise RuntimeError(
            f"{description} завершено с ошибкой:\n"
            f"{error_message}"
        )


def validate_platform() -> None:
    if platform.system() != "Darwin":
        raise RuntimeError(
            "DMG можно собрать только на macOS."
        )


def validate_app_bundle(
    bundle_path: Path,
    executable_name: str,
) -> None:
    if not bundle_path.exists():
        raise FileNotFoundError(
            f"Приложение не найдено:\n{bundle_path}\n\n"
            "Сначала запусти:\n"
            "python scripts/build.py"
        )

    if not bundle_path.is_dir():
        raise RuntimeError(
            f"Путь не является .app-пакетом:\n"
            f"{bundle_path}"
        )

    executable_path = (
        bundle_path
        / "Contents"
        / "MacOS"
        / executable_name
    )

    if not executable_path.exists():
        raise FileNotFoundError(
            "Исполняемый файл внутри .app не найден:\n"
            f"{executable_path}"
        )

    if not executable_path.is_file():
        raise RuntimeError(
            "Исполняемый путь не является файлом:\n"
            f"{executable_path}"
        )

    if executable_path.stat().st_mode & 0o111 == 0:
        raise RuntimeError(
            "Исполняемый файл не имеет права запуска:\n"
            f"{executable_path}"
        )


def validate_builds() -> None:
    validate_app_bundle(
        bundle_path=APPLICATION_PATH,
        executable_name=APP_NAME,
    )

    validate_app_bundle(
        bundle_path=UPDATER_PATH,
        executable_name=UPDATER_NAME,
    )


def prepare_release_directory() -> None:
    RELEASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    if DMG_PATH.exists():
        DMG_PATH.unlink()


def copy_applications(
    staging_dir: Path,
) -> None:
    shutil.copytree(
        APPLICATION_PATH,
        staging_dir / APPLICATION_PATH.name,
        symlinks=True,
    )

    shutil.copytree(
        UPDATER_PATH,
        staging_dir / UPDATER_PATH.name,
        symlinks=True,
    )


def create_applications_link(
    staging_dir: Path,
) -> None:
    applications_link = (
        staging_dir
        / "Applications"
    )

    applications_link.symlink_to(
        "/Applications",
        target_is_directory=True,
    )


def create_launcher_file(
    staging_dir: Path,
) -> None:
    launcher_path = (
        staging_dir
        / "Запустить AntiArchiveScanner.command"
    )

    launcher_script = f"""#!/bin/bash

APPLICATION="/Applications/{APP_NAME}.app"

if [ -d "$APPLICATION" ]; then
    open "$APPLICATION"
    exit 0
fi

CURRENT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLED_APPLICATION="$CURRENT_DIR/{APP_NAME}.app"

if [ -d "$BUNDLED_APPLICATION" ]; then
    open "$BUNDLED_APPLICATION"
    exit 0
fi

osascript -e 'display dialog "AntiArchiveScanner не найден. Перетащите приложение в папку Applications." buttons {{"OK"}} default button "OK" with icon caution'
exit 1
"""

    launcher_path.write_text(
        launcher_script,
        encoding="utf-8",
    )

    launcher_path.chmod(0o755)


def create_update_launcher_file(
    staging_dir: Path,
) -> None:
    launcher_path = (
        staging_dir
        / "Проверить обновления.command"
    )

    launcher_script = f"""#!/bin/bash

UPDATER="/Applications/{UPDATER_NAME}.app"

if [ -d "$UPDATER" ]; then
    open "$UPDATER"
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
        launcher_script,
        encoding="utf-8",
    )

    launcher_path.chmod(0o755)


def copy_documentation(
    staging_dir: Path,
) -> None:
    readme_path = PROJECT_ROOT / "README.md"

    if readme_path.exists():
        shutil.copy2(
            readme_path,
            staging_dir / "README.md",
        )

    install_instructions = (
        "Установка AntiArchiveScanner\n"
        "==============================\n\n"
        "1. Перетащите AntiArchiveScanner.app "
        "в папку Applications.\n"
        "2. Перетащите AntiArchiveScannerUpdater.app "
        "в папку Applications.\n"
        "3. Запустите AntiArchiveScanner из Applications "
        "или через файл запуска.\n"
        "4. Для проверки обновлений запустите "
        "AntiArchiveScannerUpdater.\n"
    )

    instructions_path = (
        staging_dir
        / "INSTALL.txt"
    )

    instructions_path.write_text(
        install_instructions,
        encoding="utf-8",
    )


def copy_background(
    staging_dir: Path,
) -> None:
    source_background = (
        PROJECT_ROOT
        / "resources"
        / "dmg-background.png"
    )

    if not source_background.exists():
        return

    background_dir = (
        staging_dir
        / ".background"
    )

    background_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copy2(
        source_background,
        background_dir / source_background.name,
    )


def prepare_staging_directory(
    staging_dir: Path,
) -> None:
    copy_applications(staging_dir)
    create_applications_link(staging_dir)
    create_launcher_file(staging_dir)
    create_update_launcher_file(staging_dir)
    copy_documentation(staging_dir)
    copy_background(staging_dir)


def calculate_dmg_size_mb(
    staging_dir: Path,
) -> int:
    total_size = 0

    for path in staging_dir.rglob("*"):
        if path.is_file() and not path.is_symlink():
            total_size += path.stat().st_size

    size_mb = total_size / 1024 / 1024

    return max(
        150,
        int(size_mb * 1.5) + 50,
    )


def create_dmg(
    staging_dir: Path,
) -> None:
    dmg_size_mb = calculate_dmg_size_mb(
        staging_dir
    )

    run_command(
        [
            "hdiutil",
            "create",
            "-volname",
            VOLUME_NAME,
            "-srcfolder",
            str(staging_dir),
            "-ov",
            "-format",
            "UDZO",
            "-imagekey",
            "zlib-level=9",
            "-size",
            f"{dmg_size_mb}m",
            str(DMG_PATH),
        ],
        "Создание установочного DMG",
    )


def verify_dmg() -> None:
    if not DMG_PATH.exists():
        raise FileNotFoundError(
            "DMG не был создан:\n"
            f"{DMG_PATH}"
        )

    if not DMG_PATH.is_file():
        raise RuntimeError(
            "Путь DMG не является файлом:\n"
            f"{DMG_PATH}"
        )

    if DMG_PATH.stat().st_size == 0:
        raise RuntimeError(
            "Созданный DMG пуст."
        )

    run_command(
        [
            "hdiutil",
            "verify",
            str(DMG_PATH),
        ],
        "Проверка целостности DMG",
    )


def create_macos_dmg() -> Path:
    validate_platform()
    validate_builds()
    prepare_release_directory()

    with tempfile.TemporaryDirectory(
        prefix="anti_archive_scanner_dmg_"
    ) as temporary_directory:
        staging_dir = (
            Path(temporary_directory)
            / VOLUME_NAME
        )

        staging_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        prepare_staging_directory(
            staging_dir
        )

        create_dmg(
            staging_dir
        )

    verify_dmg()

    return DMG_PATH


def main() -> int:
    try:
        dmg_path = create_macos_dmg()

    except (
        RuntimeError,
        FileNotFoundError,
        OSError,
    ) as error:
        print()
        print("=" * 60)
        print("Создание DMG завершилось ошибкой")
        print("=" * 60)
        print(error)

        return 1

    print()
    print("=" * 60)
    print("DMG успешно создан")
    print("=" * 60)
    print(dmg_path)

    size_mb = (
        dmg_path.stat().st_size
        / 1024
        / 1024
    )

    print(
        f"Размер: {size_mb:.2f} MB"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())