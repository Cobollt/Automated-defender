#!/usr/bin/env python3

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
)

BUILD_DIR = (
    PROJECT_ROOT
    / "build"
)

DIST_DIR = (
    PROJECT_ROOT
    / "dist"
)

RELEASE_DIR = (
    PROJECT_ROOT
    / "release"
)

BUILD_SCRIPT = (
    PROJECT_ROOT
    / "scripts"
    / "build.py"
)

WINDOWS_PACKAGE_SCRIPT = (
    PROJECT_ROOT
    / "scripts"
    / "create_windows_installer.py"
)

MACOS_PACKAGE_SCRIPT = (
    PROJECT_ROOT
    / "scripts"
    / "create_macos_dmg.py"
)

MANIFEST_SCRIPT = (
    PROJECT_ROOT
    / "scripts"
    / "generate_manifest.py"
)


class PackagingError(
    RuntimeError
):
    pass


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
        raise PackagingError(
            f"{description} "
            "завершено с ошибкой. "
            "Код возврата: "
            f"{result.returncode}"
        )


def detect_platform(
) -> str:
    system_name = (
        platform.system()
    )

    if (
        system_name
        == "Windows"
    ):
        return "windows"

    if (
        system_name
        == "Darwin"
    ):
        return "macos"

    raise PackagingError(
        "Сборка поддерживается "
        "только на Windows "
        "и macOS. "
        "Текущая система: "
        f"{system_name}"
    )


def validate_project(
) -> None:
    required_paths = (
        PROJECT_ROOT
        / "app.py",

        PROJECT_ROOT
        / "updater.py",

        BUILD_SCRIPT,

        MANIFEST_SCRIPT,
    )

    missing = [
        path
        for path
        in required_paths
        if not path.exists()
    ]

    if missing:
        raise PackagingError(
            "Не найдены обязательные "
            "файлы:\n"
            + "\n".join(
                str(path)
                for path
                in missing
            )
        )


def clean(
) -> None:
    print_header(
        "Очистка сборки"
    )

    for directory in (
        BUILD_DIR,
        DIST_DIR,
    ):
        if directory.exists():
            print(
                "Удаление:",
                directory,
            )

            shutil.rmtree(
                directory
            )

    for spec_file in (
        PROJECT_ROOT.glob(
            "*.spec"
        )
    ):
        print(
            "Удаление:",
            spec_file,
        )

        spec_file.unlink(
            missing_ok=True
        )

    print(
        "Очистка завершена."
    )


def run_tests(
) -> None:
    run_command(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
        ],
        "Запуск тестов",
    )


def build(
) -> None:
    run_command(
        [
            sys.executable,
            str(
                BUILD_SCRIPT
            ),
        ],
        "Сборка PyInstaller",
    )


def package(
    version: str,
) -> Path:
    target_platform = (
        detect_platform()
    )

    if (
        target_platform
        == "windows"
    ):
        package_script = (
            WINDOWS_PACKAGE_SCRIPT
        )

        command = [
            sys.executable,
            str(
                package_script
            ),
            "--version",
            version,
        ]

        expected_output = (
            RELEASE_DIR
            / "windows"
            / (
                "AntiArchiveScanner-"
                "Setup.exe"
            )
        )

    else:
        package_script = (
            MACOS_PACKAGE_SCRIPT
        )

        command = [
            sys.executable,
            str(
                package_script
            ),
            "--version",
            version,
        ]

        expected_output = (
            RELEASE_DIR
            / "macos"
            / (
                "AntiArchiveScanner.dmg"
            )
        )

    if (
        not package_script.exists()
    ):
        raise PackagingError(
            "Скрипт упаковки "
            "не найден: "
            f"{package_script}"
        )

    run_command(
        command,
        (
            "Создание пакета "
            f"{target_platform}"
        ),
    )

    if (
        not expected_output.exists()
    ):
        raise PackagingError(
            "Ожидаемый файл "
            "релиза не найден: "
            f"{expected_output}"
        )

    if (
        not expected_output.is_file()
    ):
        raise PackagingError(
            "Результат упаковки "
            "не является файлом: "
            f"{expected_output}"
        )

    if (
        expected_output
        .stat()
        .st_size
        <= 0
    ):
        raise PackagingError(
            "Созданный пакет пуст: "
            f"{expected_output}"
        )

    return expected_output


def generate_manifest(
    version: str,
    require_all: bool,
) -> None:
    command = [
        sys.executable,
        str(
            MANIFEST_SCRIPT
        ),
        "--version",
        version,
    ]

    if require_all:
        command.append(
            "--require-all"
        )

    run_command(
        command,
        (
            "Генерация "
            "update-manifest.json"
        ),
    )


def release(
    version: str,
    *,
    skip_tests: bool,
    require_all: bool,
) -> None:
    validate_project()

    clean()

    if not skip_tests:
        run_tests()

    build()

    package_path = (
        package(
            version
        )
    )

    generate_manifest(
        version=version,
        require_all=(
            require_all
        ),
    )

    print_header(
        "Релиз подготовлен"
    )

    print(
        "Платформа:",
        detect_platform(),
    )

    print(
        "Версия:",
        version,
    )

    print(
        "Пакет:",
        package_path,
    )

    print(
        "Manifest:",
        RELEASE_DIR
        / "update-manifest.json",
    )


def parse_arguments(
) -> argparse.Namespace:
    parser = (
        argparse.ArgumentParser(
            description=(
                "Build and package "
                "AntiArchiveScanner."
            )
        )
    )

    parser.add_argument(
        "command",
        choices=(
            "clean",
            "test",
            "build",
            "package",
            "manifest",
            "release",
        ),
    )

    parser.add_argument(
        "--version",
        default="1.0.0",
        help=(
            "Версия релиза, "
            "например 1.0.1."
        ),
    )

    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help=(
            "Не запускать pytest "
            "перед release."
        ),
    )

    parser.add_argument(
        "--require-all",
        action="store_true",
        help=(
            "При генерации manifest "
            "требовать наличие "
            "и Windows, и macOS пакета."
        ),
    )

    return parser.parse_args()


def main(
) -> int:
    arguments = (
        parse_arguments()
    )

    try:
        validate_project()

        if (
            arguments.command
            == "clean"
        ):
            clean()

        elif (
            arguments.command
            == "test"
        ):
            run_tests()

        elif (
            arguments.command
            == "build"
        ):
            build()

        elif (
            arguments.command
            == "package"
        ):
            package_path = (
                package(
                    arguments.version
                )
            )

            print_header(
                "Пакет создан"
            )

            print(
                "Версия:",
                arguments.version,
            )

            print(
                "Файл:",
                package_path,
            )

        elif (
            arguments.command
            == "manifest"
        ):
            generate_manifest(
                version=(
                    arguments.version
                ),
                require_all=(
                    arguments
                    .require_all
                ),
            )

        elif (
            arguments.command
            == "release"
        ):
            release(
                version=(
                    arguments.version
                ),
                skip_tests=(
                    arguments
                    .skip_tests
                ),
                require_all=(
                    arguments
                    .require_all
                ),
            )

        return 0

    except (
        PackagingError,
        FileNotFoundError,
        OSError,
    ) as error:
        print_header(
            "Операция завершилась "
            "ошибкой"
        )

        print(
            error
        )

        return 1

    except KeyboardInterrupt:
        print()

        print(
            "Операция остановлена "
            "пользователем."
        )

        return 130


if __name__ == "__main__":
    raise SystemExit(
        main()
    )