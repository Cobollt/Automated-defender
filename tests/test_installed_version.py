import plistlib
from pathlib import Path

from infrastructure.update import (
    installed_version,
)


def test_environment_version_has_priority(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        (
            "ANTIARCHIVESCANNER_"
            "VERSION"
        ),
        "1.2.3",
    )

    assert (
        installed_version
        .detect_installed_version()
        == "1.2.3"
    )


def test_v_prefix_is_normalized(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        (
            "ANTIARCHIVESCANNER_"
            "VERSION"
        ),
        "v2.0.1",
    )

    assert (
        installed_version
        .detect_installed_version()
        == "2.0.1"
    )


def test_invalid_environment_version_falls_back(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        (
            "ANTIARCHIVESCANNER_"
            "VERSION"
        ),
        "invalid-version",
    )

    monkeypatch.setattr(
        installed_version.platform,
        "system",
        lambda: "Linux",
    )

    result = (
        installed_version
        .detect_installed_version()
    )

    assert result


def test_find_info_plist(
    tmp_path: Path,
) -> None:
    bundle = (
        tmp_path
        / "Test.app"
    )

    executable = (
        bundle
        / "Contents"
        / "MacOS"
        / "Test"
    )

    executable.parent.mkdir(
        parents=True
    )

    executable.write_bytes(
        b"binary"
    )

    info_plist = (
        bundle
        / "Contents"
        / "Info.plist"
    )

    with info_plist.open(
        "wb"
    ) as target:
        plistlib.dump(
            {
                (
                    "CFBundleShort"
                    "VersionString"
                ): "1.5.0",
            },
            target,
        )

    detected = (
        installed_version
        ._find_info_plist(
            executable
        )
    )

    assert (
        detected
        == info_plist
    )


def test_macos_version_from_bundle(
    tmp_path: Path,
    monkeypatch,
) -> None:
    bundle = (
        tmp_path
        / "AntiArchiveScannerUpdater.app"
    )

    executable = (
        bundle
        / "Contents"
        / "MacOS"
        / "AntiArchiveScannerUpdater"
    )

    executable.parent.mkdir(
        parents=True
    )

    executable.write_bytes(
        b"binary"
    )

    info_plist = (
        bundle
        / "Contents"
        / "Info.plist"
    )

    with info_plist.open(
        "wb"
    ) as target:
        plistlib.dump(
            {
                (
                    "CFBundleShort"
                    "VersionString"
                ): "3.4.5",
            },
            target,
        )

    monkeypatch.setattr(
        installed_version.sys,
        "executable",
        str(
            executable
        ),
    )

    assert (
        installed_version
        ._version_from_macos_bundle()
        == "3.4.5"
    )