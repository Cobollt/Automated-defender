import json
import os
from pathlib import Path

import pytest

from infrastructure.local_quarantine import (
    LocalQuarantineProvider,
)
from utils.hashing import (
    calculate_sha256,
)


def test_file_is_moved_to_local_quarantine(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "danger.exe"
    )

    source_file.write_bytes(
        b"MZ test"
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    provider = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
    )

    result = provider.quarantine(
        source_file
    )

    assert result.success is True

    assert (
        result.provider_name
        == (
            "AntiArchiveScanner "
            "Local Quarantine"
        )
    )

    assert (
        not source_file.exists()
    )

    assert (
        result.quarantine_path
        is not None
    )

    assert (
        result.quarantine_path
        .exists()
    )

    assert (
        result.quarantine_path
        .parent
        == quarantine_dir
    )

    assert (
        result.quarantine_path
        .suffix
        == ".quarantine"
    )


def test_quarantine_metadata_is_created(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "danger.txt"
    )

    source_file.write_text(
        "test",
        encoding="utf-8",
    )

    original_path = (
        source_file.resolve()
    )

    original_sha256 = (
        calculate_sha256(
            source_file
        )
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    result = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
        .quarantine(
            source_file
        )
    )

    assert result.success is True

    assert (
        result.quarantine_path
        is not None
    )

    metadata_files = list(
        quarantine_dir.glob(
            "*.json"
        )
    )

    assert (
        len(metadata_files)
        == 1
    )

    metadata = json.loads(
        metadata_files[0]
        .read_text(
            encoding="utf-8"
        )
    )

    assert (
        metadata[
            "quarantine_id"
        ]
    )

    assert (
        metadata[
            "original_name"
        ]
        == "danger.txt"
    )

    assert (
        metadata[
            "original_path"
        ]
        == str(
            original_path
        )
    )

    assert (
        metadata[
            "stored_name"
        ]
        == (
            result
            .quarantine_path
            .name
        )
    )

    assert (
        metadata[
            "sha256"
        ]
        == original_sha256
    )

    assert (
        metadata[
            "provider"
        ]
        == (
            "AntiArchiveScanner "
            "Local Quarantine"
        )
    )

    assert (
        metadata[
            "quarantined_at"
        ]
    )


def test_quarantined_file_keeps_original_content(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "danger.bin"
    )

    original_content = (
        b"important suspicious content"
    )

    source_file.write_bytes(
        original_content
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    result = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
        .quarantine(
            source_file
        )
    )

    assert result.success is True

    assert (
        result.quarantine_path
        is not None
    )

    assert (
        result
        .quarantine_path
        .read_bytes()
        == original_content
    )


def test_original_extension_is_removed(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "danger.exe"
    )

    source_file.write_bytes(
        b"MZ test"
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    result = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
        .quarantine(
            source_file
        )
    )

    assert result.success is True

    assert (
        result.quarantine_path
        is not None
    )

    assert (
        result.quarantine_path
        .suffix
        == ".quarantine"
    )

    assert (
        ".exe"
        not in (
            result
            .quarantine_path
            .name
        )
    )


def test_missing_file_cannot_be_quarantined(
    tmp_path: Path,
) -> None:
    missing_file = (
        tmp_path
        / "missing.txt"
    )

    provider = (
        LocalQuarantineProvider(
            quarantine_dir=(
                tmp_path
                / "quarantine"
            )
        )
    )

    result = provider.quarantine(
        missing_file
    )

    assert result.success is False

    assert (
        result.quarantine_path
        is None
    )

    assert (
        "не существует"
        in (
            result.message
            or ""
        ).lower()
    )


def test_directory_cannot_be_quarantined(
    tmp_path: Path,
) -> None:
    directory = (
        tmp_path
        / "folder"
    )

    directory.mkdir()

    provider = (
        LocalQuarantineProvider(
            quarantine_dir=(
                tmp_path
                / "quarantine"
            )
        )
    )

    result = provider.quarantine(
        directory
    )

    assert result.success is False

    assert (
        result.quarantine_path
        is None
    )

    assert directory.exists()

    assert (
        "только обычные файлы"
        in (
            result.message
            or ""
        ).lower()
    )


def test_symlink_cannot_be_quarantined(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "target.txt"
    )

    source_file.write_text(
        "target",
        encoding="utf-8",
    )

    symlink = (
        tmp_path
        / "link.txt"
    )

    try:
        symlink.symlink_to(
            source_file
        )

    except (
        OSError,
        NotImplementedError,
    ):
        pytest.skip(
            "Symlinks are not "
            "supported on this system."
        )

    provider = (
        LocalQuarantineProvider(
            quarantine_dir=(
                tmp_path
                / "quarantine"
            )
        )
    )

    result = provider.quarantine(
        symlink
    )

    assert result.success is False

    assert (
        source_file.exists()
    )

    assert (
        symlink.exists()
    )

    assert (
        "символические ссылки"
        in (
            result.message
            or ""
        ).lower()
    )


def test_quarantine_directory_is_created_automatically(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "danger.txt"
    )

    source_file.write_text(
        "test",
        encoding="utf-8",
    )

    quarantine_dir = (
        tmp_path
        / "nested"
        / "quarantine"
    )

    assert (
        not quarantine_dir.exists()
    )

    result = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
        .quarantine(
            source_file
        )
    )

    assert result.success is True

    assert (
        quarantine_dir.exists()
    )


@pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "Windows chmod does not "
        "implement POSIX 0o600 "
        "permission semantics."
    ),
)
def test_quarantined_file_permissions_are_restricted(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "danger.txt"
    )

    source_file.write_text(
        "test",
        encoding="utf-8",
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    result = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
        .quarantine(
            source_file
        )
    )

    assert result.success is True

    assert (
        result.quarantine_path
        is not None
    )

    permissions = (
        result
        .quarantine_path
        .stat()
        .st_mode
        & 0o777
    )

    assert (
        permissions
        == 0o600
    )


@pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "Windows chmod does not "
        "implement POSIX 0o600 "
        "permission semantics."
    ),
)
def test_metadata_permissions_are_restricted(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "danger.txt"
    )

    source_file.write_text(
        "test",
        encoding="utf-8",
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    result = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
        .quarantine(
            source_file
        )
    )

    assert result.success is True

    metadata_path = next(
        quarantine_dir.glob(
            "*.json"
        )
    )

    permissions = (
        metadata_path
        .stat()
        .st_mode
        & 0o777
    )

    assert (
        permissions
        == 0o600
    )


@pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "Windows chmod does not "
        "implement POSIX 0o700 "
        "permission semantics."
    ),
)
def test_quarantine_directory_permissions_are_restricted(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "danger.txt"
    )

    source_file.write_text(
        "test",
        encoding="utf-8",
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    result = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
        .quarantine(
            source_file
        )
    )

    assert result.success is True

    permissions = (
        quarantine_dir
        .stat()
        .st_mode
        & 0o777
    )

    assert (
        permissions
        == 0o700
    )


def test_metadata_and_quarantined_file_have_same_identifier(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "danger.txt"
    )

    source_file.write_text(
        "test",
        encoding="utf-8",
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    result = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
        .quarantine(
            source_file
        )
    )

    assert result.success is True

    assert (
        result.quarantine_path
        is not None
    )

    metadata_path = next(
        quarantine_dir.glob(
            "*.json"
        )
    )

    quarantine_identifier = (
        result.quarantine_path
        .stem
    )

    metadata_identifier = (
        metadata_path.stem
    )

    assert (
        quarantine_identifier
        == metadata_identifier
    )


def test_metadata_is_written_atomically(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "danger.txt"
    )

    source_file.write_text(
        "test",
        encoding="utf-8",
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    result = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
        .quarantine(
            source_file
        )
    )

    assert result.success is True

    assert (
        list(
            quarantine_dir.glob(
                "*.json.tmp"
            )
        )
        == []
    )

    assert (
        len(
            list(
                quarantine_dir.glob(
                    "*.json"
                )
            )
        )
        == 1
    )


def test_rollback_restores_file_when_metadata_write_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_file = (
        tmp_path
        / "danger.txt"
    )

    original_content = (
        b"restore me"
    )

    source_file.write_bytes(
        original_content
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    provider = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
    )

    def failing_metadata_write(
        metadata_path: Path,
        metadata: dict,
    ) -> None:
        raise OSError(
            "Simulated metadata "
            "write failure"
        )

    monkeypatch.setattr(
        provider,
        "_write_metadata_atomically",
        failing_metadata_write,
    )

    result = provider.quarantine(
        source_file
    )

    assert result.success is False

    assert source_file.exists()

    assert (
        source_file.read_bytes()
        == original_content
    )

    quarantine_files = list(
        quarantine_dir.glob(
            "*.quarantine"
        )
    )

    assert (
        quarantine_files
        == []
    )

    assert (
        list(
            quarantine_dir.glob(
                "*.json"
            )
        )
        == []
    )

    assert (
        list(
            quarantine_dir.glob(
                "*.tmp"
            )
        )
        == []
    )


def test_sha256_matches_quarantined_content(
    tmp_path: Path,
) -> None:
    source_file = (
        tmp_path
        / "danger.dat"
    )

    source_file.write_bytes(
        b"hash verification content"
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    result = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
        .quarantine(
            source_file
        )
    )

    assert result.success is True

    assert (
        result.quarantine_path
        is not None
    )

    metadata_path = next(
        quarantine_dir.glob(
            "*.json"
        )
    )

    metadata = json.loads(
        metadata_path.read_text(
            encoding="utf-8"
        )
    )

    quarantined_sha256 = (
        calculate_sha256(
            result.quarantine_path
        )
    )

    assert (
        metadata[
            "sha256"
        ]
        == quarantined_sha256
    )


def test_two_files_receive_different_quarantine_identifiers(
    tmp_path: Path,
) -> None:
    first_file = (
        tmp_path
        / "first.exe"
    )

    second_file = (
        tmp_path
        / "second.exe"
    )

    first_file.write_bytes(
        b"first"
    )

    second_file.write_bytes(
        b"second"
    )

    quarantine_dir = (
        tmp_path
        / "quarantine"
    )

    provider = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_dir
            )
        )
    )

    first_result = (
        provider.quarantine(
            first_file
        )
    )

    second_result = (
        provider.quarantine(
            second_file
        )
    )

    assert (
        first_result.success
        is True
    )

    assert (
        second_result.success
        is True
    )

    assert (
        first_result
        .quarantine_path
        is not None
    )

    assert (
        second_result
        .quarantine_path
        is not None
    )

    assert (
        first_result
        .quarantine_path
        != second_result
        .quarantine_path
    )


def test_quarantine_directory_symlink_is_rejected(
    tmp_path: Path,
) -> None:
    real_directory = (
        tmp_path
        / "real-quarantine"
    )

    real_directory.mkdir()

    quarantine_link = (
        tmp_path
        / "quarantine"
    )

    try:
        quarantine_link.symlink_to(
            real_directory,
            target_is_directory=True,
        )

    except (
        OSError,
        NotImplementedError,
    ):
        pytest.skip(
            "Directory symlinks are "
            "not supported on this system."
        )

    source_file = (
        tmp_path
        / "danger.exe"
    )

    source_file.write_bytes(
        b"test"
    )

    result = (
        LocalQuarantineProvider(
            quarantine_dir=(
                quarantine_link
            )
        )
        .quarantine(
            source_file
        )
    )

    assert result.success is False

    assert source_file.exists()

    assert (
        result.quarantine_path
        is None
    )