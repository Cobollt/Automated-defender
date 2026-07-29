#!/usr/bin/env python3

import argparse
import os
import platform
import plistlib
import shutil
import subprocess
import tempfile
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

RELEASE_DIR = (
    PROJECT_ROOT
    / "release"
    / "macos"
)

APPLICATION_PATH = (
    DIST_DIR
    / f"{APP_NAME}.app"
)

UPDATER_PATH = (
    DIST_DIR
    / f"{UPDATER_NAME}.app"
)

DMG_PATH = (
    RELEASE_DIR
    / f"{APP_NAME}.dmg"
)

VOLUME_NAME = (
    APP_NAME
)

README_PATH = (
    PROJECT_ROOT
    / "README.md"
)

DMG_BACKGROUND = (
    PROJECT_ROOT
    / "resources"
    / "dmg-background.png"
)


class DmgBuildError(
    RuntimeError
):
    pass


# ---------------------------------------------------------
# Arguments
# ---------------------------------------------------------

def parse_arguments(
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create macOS DMG "
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
        raise DmgBuildError(
            "Версия приложения "
            "не может быть пустой."
        )

    try:
        parsed = Version(
            normalized
        )

    except InvalidVersion as error:
        raise DmgBuildError(
            "Некорректная версия: "
            f"{version}"
        ) from error

    return str(
        parsed
    )


# ---------------------------------------------------------
# Console helpers
# ---------------------------------------------------------

def print_header(
    title: str,
) -> None:
    print()
    print(
        "=" * 72
    )

    print(
        title
    )

    print(
        "=" * 72
    )


def run_command(
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

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
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
            or "Неизвестная ошибка."
        )

        raise DmgBuildError(
            f"{description} "
            "завершено с ошибкой:\n"
            f"{error_message}"
        )


# ---------------------------------------------------------
# Validation
# ---------------------------------------------------------

def validate_platform(
) -> None:
    if (
        platform.system()
        != "Darwin"
    ):
        raise DmgBuildError(
            "DMG можно собрать "
            "только на macOS."
        )


def validate_command(
    command_name: str,
) -> None:
    if (
        shutil.which(
            command_name
        )
        is None
    ):
        raise FileNotFoundError(
            "Не найдена системная "
            "команда: "
            f"{command_name}"
        )


def validate_app_bundle(
    bundle_path: Path,
    executable_name: str,
) -> None:
    if not bundle_path.exists():
        raise FileNotFoundError(
            "Приложение не найдено:\n"
            f"{bundle_path}\n\n"
            "Сначала выполни:\n"
            "python package_all.py build"
        )

    if not bundle_path.is_dir():
        raise DmgBuildError(
            "Путь не является "
            ".app-пакетом:\n"
            f"{bundle_path}"
        )

    contents_path = (
        bundle_path
        / "Contents"
    )

    executable_path = (
        contents_path
        / "MacOS"
        / executable_name
    )

    info_plist = (
        contents_path
        / "Info.plist"
    )

    if not contents_path.is_dir():
        raise DmgBuildError(
            "В .app отсутствует "
            "каталог Contents:\n"
            f"{bundle_path}"
        )

    if not executable_path.exists():
        raise FileNotFoundError(
            "Исполняемый файл "
            "внутри .app не найден:\n"
            f"{executable_path}"
        )

    if not executable_path.is_file():
        raise DmgBuildError(
            "Исполняемый путь "
            "не является файлом:\n"
            f"{executable_path}"
        )

    if (
        executable_path
        .stat()
        .st_mode
        & 0o111
        == 0
    ):
        raise DmgBuildError(
            "Исполняемый файл "
            "не имеет права запуска:\n"
            f"{executable_path}"
        )

    if not info_plist.exists():
        raise FileNotFoundError(
            "В .app отсутствует "
            "Info.plist:\n"
            f"{info_plist}"
        )


def validate_builds(
) -> None:
    validate_app_bundle(
        bundle_path=(
            APPLICATION_PATH
        ),
        executable_name=(
            APP_NAME
        ),
    )

    validate_app_bundle(
        bundle_path=(
            UPDATER_PATH
        ),
        executable_name=(
            UPDATER_NAME
        ),
    )


# ---------------------------------------------------------
# Code signing
# ---------------------------------------------------------

def remove_existing_signature(
    bundle_path: Path,
) -> None:
    result = subprocess.run(
        [
            "codesign",
            "--remove-signature",
            str(bundle_path),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    stderr = (
        result.stderr
        or ""
    ).strip()

    if (
        result.returncode != 0
        and "code object is not signed at all"
        not in stderr
    ):
        raise DmgBuildError(
            "Не удалось удалить "
            "старую подпись:\n"
            f"{bundle_path}\n"
            f"{stderr or 'Неизвестная ошибка.'}"
        )


def sign_bundle_for_testing(
    bundle_path: Path,
) -> None:
    remove_existing_signature(
        bundle_path
    )

    run_command(
        [
            "codesign",
            "--force",
            "--deep",
            "--sign",
            "-",
            str(bundle_path),
        ],
        f"Подписание {bundle_path.name}",
    )


def verify_bundle_signature(
    bundle_path: Path,
) -> None:
    run_command(
        [
            "codesign",
            "--verify",
            "--deep",
            "--strict",
            "--verbose=4",
            str(bundle_path),
        ],
        f"Проверка подписи {bundle_path.name}",
    )


# ---------------------------------------------------------
# Version metadata
# ---------------------------------------------------------

def version_to_bundle_version(
    version: str,
) -> str:
    parsed = Version(
        version
    )

    release = list(
        parsed.release
    )

    while (
        len(release)
        < 3
    ):
        release.append(
            0
        )

    return ".".join(
        str(part)
        for part
        in release[:3]
    )


def update_bundle_version(
    bundle_path: Path,
    version: str,
) -> None:
    info_plist_path = (
        bundle_path
        / "Contents"
        / "Info.plist"
    )

    try:
        with info_plist_path.open(
            "rb"
        ) as source:
            plist_data = (
                plistlib.load(
                    source
                )
            )

    except (
        OSError,
        plistlib.InvalidFileException,
    ) as error:
        raise DmgBuildError(
            "Не удалось прочитать "
            "Info.plist:\n"
            f"{info_plist_path}"
        ) from error

    plist_data[
        "CFBundleShortVersionString"
    ] = version

    plist_data[
        "CFBundleVersion"
    ] = (
        version_to_bundle_version(
            version
        )
    )

    temporary_path = (
        info_plist_path
        .with_name(
            "Info.plist.tmp"
        )
    )

    temporary_path.unlink(
        missing_ok=True
    )

    try:
        with temporary_path.open(
            "wb"
        ) as target:
            plistlib.dump(
                plist_data,
                target,
                fmt=(
                    plistlib
                    .FMT_BINARY
                    if (
                        info_plist_path
                        .read_bytes()
                        .startswith(
                            b"bplist"
                        )
                    )
                    else plistlib.FMT_XML
                ),
                sort_keys=False,
            )

            target.flush()

            os.fsync(
                target.fileno()
            )

        temporary_path.replace(
            info_plist_path
        )

    except Exception:
        temporary_path.unlink(
            missing_ok=True
        )

        raise


# ---------------------------------------------------------
# Release directory
# ---------------------------------------------------------

def prepare_release_directory(
) -> None:
    RELEASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    DMG_PATH.unlink(
        missing_ok=True
    )

    for temporary_file in (
        RELEASE_DIR.glob(
            "*.tmp"
        )
    ):
        temporary_file.unlink(
            missing_ok=True
        )


# ---------------------------------------------------------
# Staging
# ---------------------------------------------------------

def copy_main_application(
    staging_dir: Path,
) -> Path:
    staged_application = (
        staging_dir
        / f"{APP_NAME}.app"
    )

    shutil.copytree(
        APPLICATION_PATH,
        staged_application,
        symlinks=True,
    )

    return staged_application


def embed_updater(
    staged_application: Path,
    version: str,
) -> Path:
    updater_container = (
        staged_application
        / "Contents"
        / "Resources"
        / "updater"
    )

    updater_container.mkdir(
        parents=True,
        exist_ok=True,
    )

    embedded_updater = (
        updater_container
        / f"{UPDATER_NAME}.app"
    )

    if embedded_updater.exists():
        shutil.rmtree(
            embedded_updater
        )

    shutil.copytree(
        UPDATER_PATH,
        embedded_updater,
        symlinks=True,
    )

    update_bundle_version(
        embedded_updater,
        version,
    )

    return embedded_updater


def create_applications_link(
    staging_dir: Path,
) -> None:
    applications_link = (
        staging_dir
        / "Applications"
    )

    if (
        applications_link.exists()
        or applications_link.is_symlink()
    ):
        applications_link.unlink()

    applications_link.symlink_to(
        "/Applications",
        target_is_directory=True,
    )


def create_launcher_file(
    staging_dir: Path,
) -> None:
    launcher_path = (
        staging_dir
        / (
            "Запустить "
            "AntiArchiveScanner.command"
        )
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

osascript -e 'display dialog "AntiArchiveScanner не найден. Перетащите AntiArchiveScanner.app в папку Applications." buttons {{"OK"}} default button "OK" with icon caution'

exit 1
"""

    launcher_path.write_text(
        launcher_script,
        encoding="utf-8",
    )

    launcher_path.chmod(
        0o755
    )


def create_update_launcher_file(
    staging_dir: Path,
) -> None:
    launcher_path = (
        staging_dir
        / "Проверить обновления.command"
    )

    launcher_script = f"""#!/bin/bash

INSTALLED_UPDATER="/Applications/{APP_NAME}.app/Contents/Resources/updater/{UPDATER_NAME}.app"

if [ -d "$INSTALLED_UPDATER" ]; then
    open "$INSTALLED_UPDATER"
    exit 0
fi

CURRENT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLED_UPDATER="$CURRENT_DIR/{APP_NAME}.app/Contents/Resources/updater/{UPDATER_NAME}.app"

if [ -d "$BUNDLED_UPDATER" ]; then
    open "$BUNDLED_UPDATER"
    exit 0
fi

osascript -e 'display dialog "Программа обновления не найдена. Установите AntiArchiveScanner в папку Applications." buttons {{"OK"}} default button "OK" with icon caution'

exit 1
"""

    launcher_path.write_text(
        launcher_script,
        encoding="utf-8",
    )

    launcher_path.chmod(
        0o755
    )


def copy_documentation(
    staging_dir: Path,
    version: str,
) -> None:
    if README_PATH.exists():
        shutil.copy2(
            README_PATH,
            staging_dir
            / "README.md",
        )

    instructions = (
        "Установка AntiArchiveScanner\n"
        "==============================\n\n"
        f"Версия: {version}\n\n"
        "1. Перетащите AntiArchiveScanner.app "
        "в папку Applications.\n\n"
        "2. Запустите AntiArchiveScanner "
        "из папки Applications.\n\n"
        "3. Отдельно устанавливать программу "
        "обновления не требуется. "
        "Updater уже находится внутри "
        "AntiArchiveScanner.app.\n\n"
        "4. Для ручной проверки обновлений "
        "можно использовать файл "
        "\"Проверить обновления.command\" "
        "в установочном образе.\n\n"
        "Если macOS блокирует первый запуск "
        "тестовой сборки, скопируйте приложение "
        "в Applications, затем откройте его "
        "через Finder: правый клик → Открыть.\n"
    )

    instructions_path = (
        staging_dir
        / "INSTALL.txt"
    )

    instructions_path.write_text(
        instructions,
        encoding="utf-8",
    )


def copy_background(
    staging_dir: Path,
) -> None:
    if not DMG_BACKGROUND.exists():
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
        DMG_BACKGROUND,
        background_dir
        / DMG_BACKGROUND.name,
    )


def prepare_staging_directory(
    staging_dir: Path,
    version: str,
) -> Path:
    staged_application = (
        copy_main_application(
            staging_dir
        )
    )

    update_bundle_version(
        staged_application,
        version,
    )

    embedded_updater = (
        embed_updater(
            staged_application=(
                staged_application
            ),
            version=version,
        )
    )

    sign_bundle_for_testing(
        embedded_updater
    )

    verify_bundle_signature(
        embedded_updater
    )

    sign_bundle_for_testing(
        staged_application
    )

    verify_bundle_signature(
        staged_application
    )

    create_applications_link(
        staging_dir
    )

    create_launcher_file(
        staging_dir
    )

    create_update_launcher_file(
        staging_dir
    )

    copy_documentation(
        staging_dir=(
            staging_dir
        ),
        version=version,
    )

    copy_background(
        staging_dir
    )

    print()
    print(
        "Основное приложение:",
        staged_application,
    )

    print(
        "Встроенный updater:",
        embedded_updater,
    )

    return staged_application


# ---------------------------------------------------------
# DMG sizing
# ---------------------------------------------------------

def calculate_directory_size(
    directory: Path,
) -> int:
    total_size = 0

    for path in (
        directory.rglob("*")
    ):
        try:
            if (
                path.is_file()
                and not path.is_symlink()
            ):
                total_size += (
                    path.stat()
                    .st_size
                )

        except OSError:
            continue

    return total_size


def calculate_dmg_size_mb(
    staging_dir: Path,
) -> int:
    total_size_bytes = (
        calculate_directory_size(
            staging_dir
        )
    )

    total_size_mb = (
        total_size_bytes
        / 1024
        / 1024
    )

    # Минимум 150 MB.
    # Для больших приложений оставляем
    # 35% свободного места + 50 MB.
    estimated_size = int(
        total_size_mb
        * 1.35
        + 50
    )

    return max(
        150,
        estimated_size,
    )


# ---------------------------------------------------------
# DMG creation
# ---------------------------------------------------------

def create_dmg(
    staging_dir: Path,
) -> None:
    dmg_size_mb = (
        calculate_dmg_size_mb(
            staging_dir
        )
    )

    run_command(
        [
            "hdiutil",
            "create",

            "-volname",
            VOLUME_NAME,

            "-srcfolder",
            str(
                staging_dir
            ),

            "-ov",

            "-format",
            "UDZO",

            "-imagekey",
            "zlib-level=9",

            "-size",
            f"{dmg_size_mb}m",

            str(
                DMG_PATH
            ),
        ],
        "Создание DMG",
    )


# ---------------------------------------------------------
# Verification
# ---------------------------------------------------------

def verify_dmg_file(
) -> None:
    if not DMG_PATH.exists():
        raise FileNotFoundError(
            "DMG не был создан:\n"
            f"{DMG_PATH}"
        )

    if not DMG_PATH.is_file():
        raise DmgBuildError(
            "Путь DMG "
            "не является файлом:\n"
            f"{DMG_PATH}"
        )

    if (
        DMG_PATH.stat().st_size
        <= 0
    ):
        raise DmgBuildError(
            "Созданный DMG пуст."
        )


def verify_dmg_integrity(
) -> None:
    run_command(
        [
            "hdiutil",
            "verify",
            str(
                DMG_PATH
            ),
        ],
        "Проверка целостности DMG",
    )


def verify_dmg_contents(
) -> None:
    with tempfile.TemporaryDirectory(
        prefix=(
            "anti_archive_scanner_"
            "verify_"
        )
    ) as temporary_directory:
        mount_point = (
            Path(
                temporary_directory
            )
            / "mount"
        )

        mount_point.mkdir(
            parents=True,
            exist_ok=True,
        )

        attached = False

        try:
            run_command(
                [
                    "hdiutil",
                    "attach",

                    str(
                        DMG_PATH
                    ),

                    "-mountpoint",
                    str(
                        mount_point
                    ),

                    "-nobrowse",

                    "-readonly",
                ],
                "Монтирование DMG "
                "для проверки",
            )

            attached = True

            mounted_app = (
                mount_point
                / f"{APP_NAME}.app"
            )

            mounted_updater = (
                mounted_app
                / "Contents"
                / "Resources"
                / "updater"
                / (
                    f"{UPDATER_NAME}.app"
                )
            )

            applications_link = (
                mount_point
                / "Applications"
            )

            validate_app_bundle(
                bundle_path=(
                    mounted_app
                ),
                executable_name=(
                    APP_NAME
                ),
            )

            validate_app_bundle(
                bundle_path=(
                    mounted_updater
                ),
                executable_name=(
                    UPDATER_NAME
                ),
            )

            verify_bundle_signature(
                mounted_updater
            )

            verify_bundle_signature(
                mounted_app
            )

            if (
                not applications_link
                .is_symlink()
            ):
                raise DmgBuildError(
                    "В DMG отсутствует "
                    "ссылка Applications."
                )

            applications_target = (
                os.readlink(
                    applications_link
                )
            )

            if (
                applications_target
                != "/Applications"
            ):
                raise DmgBuildError(
                    "Ссылка Applications "
                    "указывает не на "
                    "/Applications."
                )

        finally:
            if attached:
                detach_result = (
                    subprocess.run(
                        [
                            "hdiutil",
                            "detach",
                            str(
                                mount_point
                            ),
                            "-force",
                        ],
                        cwd=PROJECT_ROOT,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                )

                if (
                    detach_result
                    .returncode
                    != 0
                ):
                    print(
                        "Предупреждение: "
                        "не удалось "
                        "автоматически "
                        "отмонтировать "
                        "проверочный DMG."
                    )


def verify_dmg(
) -> None:
    verify_dmg_file()

    verify_dmg_integrity()

    verify_dmg_contents()


# ---------------------------------------------------------
# Main build
# ---------------------------------------------------------

def create_macos_dmg(
    version: str,
) -> Path:
    validate_platform()

    validate_command(
        "hdiutil"
    )

    validate_command(
        "codesign"
    )

    normalized_version = (
        validate_version(
            version
        )
    )

    validate_builds()

    prepare_release_directory()

    with tempfile.TemporaryDirectory(
        prefix=(
            "anti_archive_scanner_dmg_"
        )
    ) as temporary_directory:
        staging_dir = (
            Path(
                temporary_directory
            )
            / VOLUME_NAME
        )

        staging_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        prepare_staging_directory(
            staging_dir=(
                staging_dir
            ),
            version=(
                normalized_version
            ),
        )

        create_dmg(
            staging_dir
        )

    verify_dmg()

    return DMG_PATH


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

        dmg_path = (
            create_macos_dmg(
                version
            )
        )

    except (
        DmgBuildError,
        RuntimeError,
        FileNotFoundError,
        OSError,
    ) as error:
        print_header(
            "Создание DMG "
            "завершилось ошибкой"
        )

        print(
            error
        )

        return 1

    except KeyboardInterrupt:
        print()

        print(
            "Создание DMG "
            "остановлено пользователем."
        )

        return 130

    print_header(
        "DMG успешно создан"
    )

    print(
        "Версия:",
        version,
    )

    print(
        "Файл:",
        dmg_path,
    )

    size_mb = (
        dmg_path
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