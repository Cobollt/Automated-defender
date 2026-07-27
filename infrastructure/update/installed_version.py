import os
import platform
import plistlib
import sys
from pathlib import Path

from infrastructure.update.update_config import (
    CURRENT_VERSION,
)
from infrastructure.update.update_manifest import (
    validate_version,
)


ENV_VERSION_NAME = (
    "ANTIARCHIVESCANNER_VERSION"
)


def detect_installed_version(
) -> str:
    environment_version = (
        _version_from_environment()
    )

    if environment_version:
        return environment_version

    system_name = (
        platform.system()
    )

    if system_name == "Windows":
        windows_version = (
            _version_from_windows_registry()
        )

        if windows_version:
            return windows_version

    if system_name == "Darwin":
        macos_version = (
            _version_from_macos_bundle()
        )

        if macos_version:
            return macos_version

    return _normalize_version(
        CURRENT_VERSION
    )


def _version_from_environment(
) -> str | None:
    value = (
        os.environ.get(
            ENV_VERSION_NAME
        )
    )

    if not value:
        return None

    return _safe_normalize_version(
        value
    )


def _version_from_windows_registry(
) -> str | None:
    try:
        import winreg

    except ImportError:
        return None

    registry_path = (
        r"Software\AntiArchiveScanner"
    )

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ,
        ) as key:
            value, value_type = (
                winreg.QueryValueEx(
                    key,
                    "Version",
                )
            )

    except (
        FileNotFoundError,
        OSError,
    ):
        return None

    if (
        value_type
        != winreg.REG_SZ
    ):
        return None

    return _safe_normalize_version(
        str(value)
    )


def _version_from_macos_bundle(
) -> str | None:
    executable_path = Path(
        sys.executable
    ).resolve()

    info_plist = (
        _find_info_plist(
            executable_path
        )
    )

    if info_plist is None:
        return None

    try:
        with info_plist.open(
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
    ):
        return None

    value = (
        plist_data.get(
            "CFBundleShortVersionString"
        )
        or plist_data.get(
            "CFBundleVersion"
        )
    )

    if value is None:
        return None

    return _safe_normalize_version(
        str(value)
    )


def _find_info_plist(
    executable_path: Path,
) -> Path | None:
    for parent in (
        executable_path.parents
    ):
        if (
            parent.name
            != "Contents"
        ):
            continue

        info_plist = (
            parent
            / "Info.plist"
        )

        if info_plist.is_file():
            return info_plist

    return None


def _safe_normalize_version(
    value: str,
) -> str | None:
    try:
        return _normalize_version(
            value
        )

    except Exception:
        return None


def _normalize_version(
    value: str,
) -> str:
    parsed = validate_version(
        value
    )

    return str(
        parsed
    )