#!/usr/bin/env python3

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------
# Project path
# ---------------------------------------------------------

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

# При прямом запуске:
#
# python scripts/generate_manifest.py
#
# Python добавляет в sys.path только каталог scripts.
# Поэтому вручную добавляем корень проекта до импортов
# infrastructure, utils и остальных пакетов проекта.

project_root_string = str(
    PROJECT_ROOT
)

if (
    project_root_string
    not in sys.path
):
    sys.path.insert(
        0,
        project_root_string,
    )


# ---------------------------------------------------------
# Project imports
# ---------------------------------------------------------

from infrastructure.update.update_config import (
    MACOS_INSTALLER_URL,
    WINDOWS_INSTALLER_URL,
)
from infrastructure.update.update_manifest import (
    UpdateManifest,
)
from utils.hashing import (
    calculate_sha256,
)


# ---------------------------------------------------------
# Release paths
# ---------------------------------------------------------

RELEASE_DIR = (
    PROJECT_ROOT
    / "release"
)

WINDOWS_RELEASE_DIR = (
    RELEASE_DIR
    / "windows"
)

MACOS_RELEASE_DIR = (
    RELEASE_DIR
    / "macos"
)

WINDOWS_INSTALLER = (
    WINDOWS_RELEASE_DIR
    / "AntiArchiveScanner-Setup.exe"
)

MACOS_INSTALLER = (
    MACOS_RELEASE_DIR
    / "AntiArchiveScanner.dmg"
)

MANIFEST_PATH = (
    RELEASE_DIR
    / "update-manifest.json"
)


# ---------------------------------------------------------
# Arguments
# ---------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate AntiArchiveScanner "
            "update manifest."
        )
    )

    parser.add_argument(
        "--version",
        required=True,
        help=(
            "Release version, "
            "for example 1.0.1"
        ),
    )

    parser.add_argument(
        "--require-all",
        action="store_true",
        help=(
            "Fail if Windows or "
            "macOS installer is missing."
        ),
    )

    return parser.parse_args()


# ---------------------------------------------------------
# Platform entries
# ---------------------------------------------------------

def build_platform_entry(
    installer_path: Path,
    download_url: str,
) -> dict[str, str] | None:
    if not installer_path.exists():
        return None

    if not installer_path.is_file():
        raise RuntimeError(
            "Installer path is not "
            "a regular file: "
            f"{installer_path}"
        )

    file_size = (
        installer_path
        .stat()
        .st_size
    )

    if file_size <= 0:
        raise RuntimeError(
            "Installer is empty: "
            f"{installer_path}"
        )

    sha256 = calculate_sha256(
        installer_path
    )

    return {
        "url": download_url,
        "sha256": sha256,
    }


# ---------------------------------------------------------
# Manifest
# ---------------------------------------------------------

def build_manifest_data(
    version: str,
) -> dict:
    windows = (
        build_platform_entry(
            installer_path=(
                WINDOWS_INSTALLER
            ),
            download_url=(
                WINDOWS_INSTALLER_URL
            ),
        )
    )

    macos = (
        build_platform_entry(
            installer_path=(
                MACOS_INSTALLER
            ),
            download_url=(
                MACOS_INSTALLER_URL
            ),
        )
    )

    return {
        "version": version,
        "published_at": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),
        "windows": windows,
        "macos": macos,
    }


def validate_required_platforms(
    manifest_data: dict,
) -> None:
    missing_platforms = []

    if (
        manifest_data.get(
            "windows"
        )
        is None
    ):
        missing_platforms.append(
            "Windows"
        )

    if (
        manifest_data.get(
            "macos"
        )
        is None
    ):
        missing_platforms.append(
            "macOS"
        )

    if not missing_platforms:
        return

    raise RuntimeError(
        "Missing release package(s): "
        + ", ".join(
            missing_platforms
        )
    )


# ---------------------------------------------------------
# Atomic write
# ---------------------------------------------------------

def write_manifest_atomically(
    manifest_data: dict,
) -> Path:
    RELEASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = (
        MANIFEST_PATH
        .with_name(
            MANIFEST_PATH.name
            + ".tmp"
        )
    )

    temporary_path.unlink(
        missing_ok=True
    )

    payload = (
        json.dumps(
            manifest_data,
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )

    try:
        with temporary_path.open(
            "x",
            encoding="utf-8",
            newline="\n",
        ) as target:
            target.write(
                payload
            )

            target.flush()

            os.fsync(
                target.fileno()
            )

        temporary_path.replace(
            MANIFEST_PATH
        )

    except Exception:
        temporary_path.unlink(
            missing_ok=True
        )

        raise

    return MANIFEST_PATH


# ---------------------------------------------------------
# Console output
# ---------------------------------------------------------

def print_platform_info(
    platform_name: str,
    installer_path: Path,
    entry: dict | None,
) -> None:
    print()
    print(
        platform_name
    )
    print(
        "-" * 60
    )

    if entry is None:
        print(
            "Installer: missing"
        )

        return

    file_size_mb = (
        installer_path
        .stat()
        .st_size
        / 1024
        / 1024
    )

    print(
        "Installer:",
        installer_path,
    )

    print(
        "Size:",
        f"{file_size_mb:.2f} MB",
    )

    print(
        "URL:",
        entry["url"],
    )

    print(
        "SHA-256:",
        entry["sha256"],
    )


# ---------------------------------------------------------
# Public generation function
# ---------------------------------------------------------

def generate_manifest(
    version: str,
    require_all: bool = False,
) -> Path:
    manifest_data = (
        build_manifest_data(
            version=version
        )
    )

    if require_all:
        validate_required_platforms(
            manifest_data
        )

    # Валидируем тем же классом,
    # который использует updater.
    UpdateManifest.from_dict(
        manifest_data
    )

    manifest_path = (
        write_manifest_atomically(
            manifest_data
        )
    )

    print()
    print(
        "=" * 60
    )

    print(
        "Update manifest generated"
    )

    print(
        "=" * 60
    )

    print(
        "Version:",
        version,
    )

    print_platform_info(
        platform_name="Windows",
        installer_path=(
            WINDOWS_INSTALLER
        ),
        entry=(
            manifest_data[
                "windows"
            ]
        ),
    )

    print_platform_info(
        platform_name="macOS",
        installer_path=(
            MACOS_INSTALLER
        ),
        entry=(
            manifest_data[
                "macos"
            ]
        ),
    )

    print()
    print(
        "Manifest:",
        manifest_path,
    )

    return manifest_path


# ---------------------------------------------------------
# Entry point
# ---------------------------------------------------------

def main() -> int:
    arguments = (
        parse_arguments()
    )

    try:
        generate_manifest(
            version=(
                arguments.version
            ),
            require_all=(
                arguments.require_all
            ),
        )

    except Exception as error:
        print()
        print(
            "=" * 60
        )

        print(
            "Manifest generation failed"
        )

        print(
            "=" * 60
        )

        print(
            error
        )

        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )