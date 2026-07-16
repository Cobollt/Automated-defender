#!/usr/bin/env python3

import platform
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DIST_DIR = PROJECT_ROOT / "dist"
RELEASE_DIR = PROJECT_ROOT / "release"

APP_NAME = "AntiArchiveScanner"


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
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{description} завершено с ошибкой "
            f"({result.returncode})"
        )


def clean_release_directory() -> None:
    if RELEASE_DIR.exists():
        shutil.rmtree(RELEASE_DIR)

    RELEASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def run_compile_check() -> None:
    source_paths = [
        PROJECT_ROOT / "app.py",
        PROJECT_ROOT / "config.py",
        PROJECT_ROOT / "application",
        PROJECT_ROOT / "domain",
        PROJECT_ROOT / "infrastructure",
        PROJECT_ROOT / "platform_services",
        PROJECT_ROOT / "presentation",
        PROJECT_ROOT / "utils",
        PROJECT_ROOT / "scripts",
        PROJECT_ROOT / "tests",
    ]

    existing_paths = [
        str(path)
        for path in source_paths
        if path.exists()
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
        "Запуск автоматических тестов",
    )


def build_application() -> None:
    run_command(
        [
            sys.executable,
            str(
                PROJECT_ROOT
                / "scripts"
                / "build.py"
            ),
        ],
        "Сборка приложения",
    )


def verify_macos_build() -> Path:
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

    if not application_path.exists():
        raise FileNotFoundError(
            f"Приложение macOS не найдено: "
            f"{application_path}"
        )

    if not executable_path.exists():
        raise FileNotFoundError(
            f"Исполняемый файл macOS не найден: "
            f"{executable_path}"
        )

    if not executable_path.is_file():
        raise RuntimeError(
            f"Путь не является обычным файлом: "
            f"{executable_path}"
        )

    if not executable_path.stat().st_mode & 0o111:
        raise RuntimeError(
            f"Исполняемый файл не имеет права запуска: "
            f"{executable_path}"
        )

    return application_path


def verify_windows_build() -> Path:
    application_dir = (
        DIST_DIR
        / APP_NAME
    )

    executable_path = (
        application_dir
        / f"{APP_NAME}.exe"
    )

    if not application_dir.exists():
        raise FileNotFoundError(
            f"Каталог Windows-приложения не найден: "
            f"{application_dir}"
        )

    if not executable_path.exists():
        raise FileNotFoundError(
            f"Windows-приложение не найдено: "
            f"{executable_path}"
        )

    if not executable_path.is_file():
        raise RuntimeError(
            f"Путь не является обычным файлом: "
            f"{executable_path}"
        )

    return application_dir


def copy_release_files(
    destination_dir: Path,
) -> None:
    files_to_copy = [
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "requirements.txt",
    ]

    for source_path in files_to_copy:
        if not source_path.exists():
            continue

        shutil.copy2(
            source_path,
            destination_dir / source_path.name,
        )


def create_release_info(
    destination_dir: Path,
) -> None:
    release_info = (
        f"Application: {APP_NAME}\n"
        f"Platform: {platform.system()}\n"
        f"Architecture: {platform.machine()}\n"
        f"Python: {platform.python_version()}\n"
        f"Created at: {datetime.now().isoformat()}\n"
    )

    info_path = (
        destination_dir
        / "RELEASE_INFO.txt"
    )

    info_path.write_text(
        release_info,
        encoding="utf-8",
    )


def package_macos(
    release_name: str,
) -> Path:
    application_path = verify_macos_build()

    package_dir = (
        RELEASE_DIR
        / release_name
    )

    package_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    packaged_application = (
        package_dir
        / application_path.name
    )

    shutil.copytree(
        application_path,
        packaged_application,
        symlinks=True,
    )

    copy_release_files(package_dir)
    create_release_info(package_dir)

    archive_path = shutil.make_archive(
        base_name=str(
            RELEASE_DIR / release_name
        ),
        format="zip",
        root_dir=RELEASE_DIR,
        base_dir=release_name,
    )

    shutil.rmtree(package_dir)

    return Path(archive_path)


def package_windows(
    release_name: str,
) -> Path:
    application_dir = verify_windows_build()

    package_dir = (
        RELEASE_DIR
        / release_name
    )

    shutil.copytree(
        application_dir,
        package_dir,
    )

    copy_release_files(package_dir)
    create_release_info(package_dir)

    archive_path = shutil.make_archive(
        base_name=str(
            RELEASE_DIR / release_name
        ),
        format="zip",
        root_dir=RELEASE_DIR,
        base_dir=release_name,
    )

    shutil.rmtree(package_dir)

    return Path(archive_path)


def create_release() -> Path:
    current_system = platform.system()
    current_architecture = platform.machine()

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    normalized_system = {
        "Darwin": "macOS",
        "Windows": "Windows",
    }.get(
        current_system,
        current_system,
    )

    release_name = (
        f"{APP_NAME}_"
        f"{normalized_system}_"
        f"{current_architecture}_"
        f"{timestamp}"
    )

    if current_system == "Darwin":
        return package_macos(
            release_name
        )

    if current_system == "Windows":
        return package_windows(
            release_name
        )

    raise RuntimeError(
        "Создание релиза поддерживается "
        "только на Windows и macOS."
    )


def verify_release_archive(
    archive_path: Path,
) -> None:
    if not archive_path.exists():
        raise FileNotFoundError(
            f"Архив релиза не создан: "
            f"{archive_path}"
        )

    if not archive_path.is_file():
        raise RuntimeError(
            f"Путь релиза не является файлом: "
            f"{archive_path}"
        )

    if archive_path.stat().st_size == 0:
        raise RuntimeError(
            f"Архив релиза пуст: "
            f"{archive_path}"
        )


def main() -> int:
    try:
        clean_release_directory()

        run_compile_check()
        run_tests()
        build_application()

        release_archive = create_release()

        verify_release_archive(
            release_archive
        )

    except (
        RuntimeError,
        FileNotFoundError,
        OSError,
    ) as error:
        print()
        print("=" * 60)
        print("Создание релиза завершилось ошибкой")
        print("=" * 60)
        print(error)

        return 1

    print()
    print("=" * 60)
    print("Релиз успешно создан")
    print("=" * 60)

    print()
    print("Архив релиза:")
    print(release_archive)

    print()
    print("Размер:")
    print(
        f"{release_archive.stat().st_size / 1024 / 1024:.2f} MB"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
