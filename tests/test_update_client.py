import hashlib
import json
import urllib.error
from pathlib import Path

import pytest

from infrastructure.update.update_client import (
    UpdateClient,
)
from infrastructure.update.update_manifest import (
    UpdateError,
)


class FakeResponse:
    def __init__(
        self,
        content: bytes,
    ) -> None:
        self._content = (
            content
        )

        self._offset = 0

    def __enter__(
        self,
    ) -> "FakeResponse":
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        return None

    def read(
        self,
        size: int = -1,
    ) -> bytes:
        if size < 0:
            return self._content

        if (
            self._offset
            >= len(
                self._content
            )
        ):
            return b""

        chunk = (
            self._content[
                self._offset:
                self._offset + size
            ]
        )

        self._offset += (
            len(chunk)
        )

        return chunk


def test_fetch_manifest_success(
    monkeypatch,
) -> None:
    manifest_data = {
        "version": "1.0.1",
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

    payload = json.dumps(
        manifest_data
    ).encode(
        "utf-8"
    )

    monkeypatch.setattr(
        (
            "infrastructure.update."
            "update_client."
            "urllib.request.urlopen"
        ),
        lambda *args, **kwargs: (
            FakeResponse(
                payload
            )
        ),
    )

    client = UpdateClient(
        "https://example.com/"
        "manifest.json"
    )

    manifest = (
        client.fetch_manifest()
    )

    assert (
        manifest.version
        == "1.0.1"
    )


def test_fetch_manifest_rejects_invalid_json(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        (
            "infrastructure.update."
            "update_client."
            "urllib.request.urlopen"
        ),
        lambda *args, **kwargs: (
            FakeResponse(
                b"{invalid json"
            )
        ),
    )

    client = UpdateClient(
        "https://example.com/"
        "manifest.json"
    )

    with pytest.raises(
        UpdateError
    ):
        client.fetch_manifest()


def test_fetch_manifest_handles_network_error(
    monkeypatch,
) -> None:
    def fail(
        *args,
        **kwargs,
    ):
        raise urllib.error.URLError(
            "offline"
        )

    monkeypatch.setattr(
        (
            "infrastructure.update."
            "update_client."
            "urllib.request.urlopen"
        ),
        fail,
    )

    client = UpdateClient(
        "https://example.com/"
        "manifest.json"
    )

    with pytest.raises(
        UpdateError
    ):
        client.fetch_manifest()


def test_download_update_success(
    tmp_path: Path,
    monkeypatch,
) -> None:
    content = (
        b"installer content"
    )

    expected_sha256 = (
        hashlib.sha256(
            content
        ).hexdigest()
    )

    monkeypatch.setattr(
        (
            "infrastructure.update."
            "update_client."
            "urllib.request.urlopen"
        ),
        lambda *args, **kwargs: (
            FakeResponse(
                content
            )
        ),
    )

    destination = (
        tmp_path
        / "installer.exe"
    )

    client = UpdateClient(
        "https://example.com/"
        "manifest.json"
    )

    client.download_update(
        url=(
            "https://example.com/"
            "installer.exe"
        ),
        expected_sha256=(
            expected_sha256
        ),
        destination=(
            destination
        ),
    )

    assert (
        destination.exists()
    )

    assert (
        destination.read_bytes()
        == content
    )

    assert (
        not (
            tmp_path
            / "installer.exe.part"
        ).exists()
    )


def test_bad_sha256_removes_download(
    tmp_path: Path,
    monkeypatch,
) -> None:
    content = (
        b"corrupted installer"
    )

    monkeypatch.setattr(
        (
            "infrastructure.update."
            "update_client."
            "urllib.request.urlopen"
        ),
        lambda *args, **kwargs: (
            FakeResponse(
                content
            )
        ),
    )

    destination = (
        tmp_path
        / "installer.exe"
    )

    client = UpdateClient(
        "https://example.com/"
        "manifest.json"
    )

    with pytest.raises(
        UpdateError
    ):
        client.download_update(
            url=(
                "https://example.com/"
                "installer.exe"
            ),
            expected_sha256=(
                "0" * 64
            ),
            destination=(
                destination
            ),
        )

    assert (
        not destination.exists()
    )

    assert (
        not (
            tmp_path
            / "installer.exe.part"
        ).exists()
    )


def test_network_failure_removes_partial_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fail(
        *args,
        **kwargs,
    ):
        raise urllib.error.URLError(
            "connection lost"
        )

    monkeypatch.setattr(
        (
            "infrastructure.update."
            "update_client."
            "urllib.request.urlopen"
        ),
        fail,
    )

    destination = (
        tmp_path
        / "installer.exe"
    )

    client = UpdateClient(
        "https://example.com/"
        "manifest.json"
    )

    with pytest.raises(
        UpdateError
    ):
        client.download_update(
            url=(
                "https://example.com/"
                "installer.exe"
            ),
            expected_sha256=(
                "0" * 64
            ),
            destination=(
                destination
            ),
        )

    assert (
        not destination.exists()
    )

    assert (
        not (
            tmp_path
            / "installer.exe.part"
        ).exists()
    )