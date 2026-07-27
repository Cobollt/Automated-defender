import hashlib
import json
from pathlib import Path

from scripts import (
    generate_manifest,
)


def calculate_test_sha256(
    data: bytes,
) -> str:
    return (
        hashlib.sha256(
            data
        )
        .hexdigest()
    )


def test_build_platform_entry_returns_none_for_missing_file(
    tmp_path: Path,
) -> None:
    missing_file = (
        tmp_path
        / "missing.exe"
    )

    entry = (
        generate_manifest
        .build_platform_entry(
            installer_path=(
                missing_file
            ),
            download_url=(
                "https://example.com/"
                "installer.exe"
            ),
        )
    )

    assert entry is None


def test_build_platform_entry_calculates_sha256(
    tmp_path: Path,
) -> None:
    installer = (
        tmp_path
        / "installer.exe"
    )

    content = (
        b"installer content"
    )

    installer.write_bytes(
        content
    )

    entry = (
        generate_manifest
        .build_platform_entry(
            installer_path=(
                installer
            ),
            download_url=(
                "https://example.com/"
                "installer.exe"
            ),
        )
    )

    assert entry is not None

    assert (
        entry["url"]
        == (
            "https://example.com/"
            "installer.exe"
        )
    )

    assert (
        entry["sha256"]
        == calculate_test_sha256(
            content
        )
    )


def test_require_all_fails_when_platform_is_missing(
) -> None:
    manifest_data = {
        "version": "1.0.0",
        "published_at": (
            "2026-07-27T00:00:00+00:00"
        ),
        "windows": {
            "url": (
                "https://example.com/"
                "setup.exe"
            ),
            "sha256": (
                "a" * 64
            ),
        },
        "macos": None,
    }

    try:
        generate_manifest \
            .validate_required_platforms(
                manifest_data
            )

    except RuntimeError as error:
        assert (
            "macOS"
            in str(error)
        )

    else:
        raise AssertionError(
            "Expected RuntimeError"
        )


def test_write_manifest_atomically(
    tmp_path: Path,
    monkeypatch,
) -> None:
    release_dir = (
        tmp_path
        / "release"
    )

    manifest_path = (
        release_dir
        / "update-manifest.json"
    )

    monkeypatch.setattr(
        generate_manifest,
        "RELEASE_DIR",
        release_dir,
    )

    monkeypatch.setattr(
        generate_manifest,
        "MANIFEST_PATH",
        manifest_path,
    )

    manifest_data = {
        "version": "1.0.0",
        "published_at": (
            "2026-07-27T00:00:00+00:00"
        ),
        "windows": {
            "url": (
                "https://example.com/"
                "setup.exe"
            ),
            "sha256": (
                "a" * 64
            ),
        },
        "macos": {
            "url": (
                "https://example.com/"
                "app.dmg"
            ),
            "sha256": (
                "b" * 64
            ),
        },
    }

    result = (
        generate_manifest
        .write_manifest_atomically(
            manifest_data
        )
    )

    assert (
        result
        == manifest_path
    )

    assert (
        manifest_path.exists()
    )

    assert (
        not (
            release_dir
            / "update-manifest.json.tmp"
        ).exists()
    )

    saved = json.loads(
        manifest_path.read_text(
            encoding="utf-8"
        )
    )

    assert (
        saved
        == manifest_data
    )


def test_generated_manifest_model_is_valid(
) -> None:
    manifest_data = {
        "version": "1.2.3",
        "published_at": (
            "2026-07-27T00:00:00+00:00"
        ),
        "windows": {
            "url": (
                "https://example.com/"
                "setup.exe"
            ),
            "sha256": (
                "a" * 64
            ),
        },
        "macos": {
            "url": (
                "https://example.com/"
                "app.dmg"
            ),
            "sha256": (
                "b" * 64
            ),
        },
    }

    manifest = (
        generate_manifest
        .UpdateManifest
        .from_dict(
            manifest_data
        )
    )

    assert (
        manifest.version
        == "1.2.3"
    )