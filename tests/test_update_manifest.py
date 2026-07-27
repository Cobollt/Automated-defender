import pytest

from infrastructure.update.update_manifest import (
    PlatformUpdate,
    UpdateError,
    UpdateManifest,
    is_newer_version,
)


VALID_SHA256 = (
    "a" * 64
)


def test_valid_manifest_is_parsed(
) -> None:
    manifest = (
        UpdateManifest.from_dict(
            {
                "version": (
                    "1.2.3"
                ),
                "published_at": (
                    "2026-07-27T00:00:00+00:00"
                ),
                "windows": {
                    "url": (
                        "https://example.com/"
                        "setup.exe"
                    ),
                    "sha256": (
                        VALID_SHA256
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
        )
    )

    assert (
        manifest.version
        == "1.2.3"
    )

    assert (
        manifest.windows
        is not None
    )

    assert (
        manifest.macos
        is not None
    )


def test_manifest_allows_missing_other_platform(
) -> None:
    manifest = (
        UpdateManifest.from_dict(
            {
                "version": "1.0.1",
                "windows": {
                    "url": (
                        "https://example.com/"
                        "setup.exe"
                    ),
                    "sha256": (
                        VALID_SHA256
                    ),
                },
                "macos": None,
            }
        )
    )

    assert (
        manifest.windows
        is not None
    )

    assert (
        manifest.macos
        is None
    )


def test_manifest_rejects_missing_version(
) -> None:
    with pytest.raises(
        UpdateError
    ):
        UpdateManifest.from_dict(
            {
                "windows": {
                    "url": (
                        "https://example.com/"
                        "setup.exe"
                    ),
                    "sha256": (
                        VALID_SHA256
                    ),
                },
            }
        )


def test_manifest_rejects_invalid_version(
) -> None:
    with pytest.raises(
        UpdateError
    ):
        UpdateManifest.from_dict(
            {
                "version": (
                    "not-a-version"
                ),
                "windows": {
                    "url": (
                        "https://example.com/"
                        "setup.exe"
                    ),
                    "sha256": (
                        VALID_SHA256
                    ),
                },
            }
        )


def test_manifest_rejects_empty_platforms(
) -> None:
    with pytest.raises(
        UpdateError
    ):
        UpdateManifest.from_dict(
            {
                "version": (
                    "1.0.0"
                ),
                "windows": None,
                "macos": None,
            }
        )


def test_invalid_sha256_is_rejected(
) -> None:
    with pytest.raises(
        UpdateError
    ):
        PlatformUpdate(
            url=(
                "https://example.com/"
                "setup.exe"
            ),
            sha256="1234",
        )


def test_non_hex_sha256_is_rejected(
) -> None:
    with pytest.raises(
        UpdateError
    ):
        PlatformUpdate(
            url=(
                "https://example.com/"
                "setup.exe"
            ),
            sha256=(
                "z" * 64
            ),
        )


def test_invalid_url_is_rejected(
) -> None:
    with pytest.raises(
        UpdateError
    ):
        PlatformUpdate(
            url=(
                "not-a-url"
            ),
            sha256=(
                VALID_SHA256
            ),
        )


def test_windows_platform_update(
) -> None:
    manifest = (
        UpdateManifest.from_dict(
            {
                "version": (
                    "1.0.1"
                ),
                "windows": {
                    "url": (
                        "https://example.com/"
                        "setup.exe"
                    ),
                    "sha256": (
                        VALID_SHA256
                    ),
                },
                "macos": None,
            }
        )
    )

    update = (
        manifest.platform_update(
            "Windows"
        )
    )

    assert (
        update.url.endswith(
            "setup.exe"
        )
    )


def test_missing_current_platform_is_rejected(
) -> None:
    manifest = (
        UpdateManifest.from_dict(
            {
                "version": (
                    "1.0.1"
                ),
                "windows": None,
                "macos": {
                    "url": (
                        "https://example.com/"
                        "app.dmg"
                    ),
                    "sha256": (
                        VALID_SHA256
                    ),
                },
            }
        )
    )

    with pytest.raises(
        UpdateError
    ):
        manifest.platform_update(
            "Windows"
        )


def test_unsupported_platform_is_rejected(
) -> None:
    manifest = (
        UpdateManifest.from_dict(
            {
                "version": (
                    "1.0.1"
                ),
                "windows": {
                    "url": (
                        "https://example.com/"
                        "setup.exe"
                    ),
                    "sha256": (
                        VALID_SHA256
                    ),
                },
            }
        )
    )

    with pytest.raises(
        UpdateError
    ):
        manifest.platform_update(
            "Linux"
        )


def test_semantic_version_comparison(
) -> None:
    assert (
        is_newer_version(
            "1.9.0",
            "1.10.0",
        )
        is True
    )

    assert (
        is_newer_version(
            "1.10.0",
            "1.9.0",
        )
        is False
    )


def test_equal_version_is_not_newer(
) -> None:
    assert (
        is_newer_version(
            "1.0.0",
            "1.0.0",
        )
        is False
    )


def test_v_prefix_is_supported(
) -> None:
    assert (
        is_newer_version(
            "v1.0.0",
            "v1.0.1",
        )
        is True
    )