import os
import time
import zipfile
from pathlib import Path

import pytest

from application.scanner_service import (
    ScannerService,
)
from config import AppConfig
from domain.enums import (
    RiskLevel,
    ScanStatus,
)
from infrastructure.temp_manager import (
    TempManager,
)


def test_scanner_checks_single_safe_file(
    safe_text_file: Path,
) -> None:
    scanner = ScannerService()

    result = scanner.scan(
        safe_text_file
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert (
        result.error_message
        is None
    )

    assert (
        result.target_path
        == safe_text_file.resolve()
    )

    assert result.target_sha256

    assert (
        result.total_files_checked
        == 1
    )

    assert (
        result.total_threats_found
        == 0
    )

    assert (
        result.risk_score
        == 0
    )

    assert (
        result.risk_level
        == RiskLevel.SAFE
    )

    assert (
        len(
            result.file_results
        )
        == 1
    )

    file_result = (
        result.file_results[0]
    )

    assert (
        file_result.file_path
        == safe_text_file.resolve()
    )

    assert (
        file_result.relative_path
        == safe_text_file.name
    )

    assert (
        file_result.sha256
        == result.target_sha256
    )


def test_scanner_returns_failure_for_missing_file(
    tmp_path: Path,
) -> None:
    missing_file = (
        tmp_path
        / "missing.zip"
    )

    result = (
        ScannerService()
        .scan(
            missing_file
        )
    )

    assert (
        result.status
        == ScanStatus.FAILED
    )

    assert (
        result.error_message
        is not None
    )

    assert (
        result.target_sha256
        is None
    )

    assert (
        result.total_files_checked
        == 0
    )

    assert (
        result.file_results
        == []
    )


def test_scanner_returns_failure_for_directory(
    tmp_path: Path,
) -> None:
    result = (
        ScannerService()
        .scan(
            tmp_path
        )
    )

    assert (
        result.status
        == ScanStatus.FAILED
    )

    assert (
        result.error_message
        is not None
    )

    assert (
        "regular file"
        in result.error_message
    )


def test_scanner_rejects_file_above_input_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    file_path = (
        tmp_path
        / "large.bin"
    )

    file_path.write_bytes(
        b"1234567890"
    )

    monkeypatch.setattr(
        AppConfig,
        "MAX_INPUT_FILE_SIZE_MB",
        0,
    )

    scanner = ScannerService()

    result = scanner.scan(
        file_path
    )

    assert (
        result.status
        == ScanStatus.FAILED
    )

    assert (
        result.error_message
        is not None
    )

    assert (
        "maximum allowed size"
        in result.error_message
    )

    assert (
        result.target_sha256
        is None
    )


def test_scanner_checks_files_inside_zip_archive(
    tmp_path: Path,
) -> None:
    archive_path = (
        tmp_path
        / "files.zip"
    )

    with zipfile.ZipFile(
        archive_path,
        "w",
    ) as archive:
        archive.writestr(
            "safe.txt",
            "hello",
        )

        archive.writestr(
            "folder/danger.ps1",
            (
                "powershell "
                "-EncodedCommand test"
            ),
        )

    result = (
        ScannerService()
        .scan(
            archive_path
        )
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert (
        result.error_message
        is None
    )

    assert result.target_sha256

    assert (
        result.total_files_checked
        == 2
    )

    assert (
        result.total_threats_found
        > 0
    )

    assert (
        result.risk_score
        > 0
    )

    assert (
        result.risk_level
        != RiskLevel.SAFE
    )

    relative_paths = {
        file_result.relative_path
        for file_result
        in result.file_results
    }

    assert (
        "safe.txt"
        in relative_paths
    )

    assert (
        "folder/danger.ps1"
        in relative_paths
    )

    assert all(
        file_result.relative_path
        is not None
        for file_result
        in result.file_results
    )

    assert all(
        not (
            file_result
            .relative_path
            .startswith(
                "/tmp/"
            )
        )
        for file_result
        in result.file_results
        if (
            file_result
            .relative_path
        )
    )


def test_scanner_detects_nested_archive(
    tmp_path: Path,
) -> None:
    inner_archive = (
        tmp_path
        / "inner.zip"
    )

    with zipfile.ZipFile(
        inner_archive,
        "w",
    ) as archive:
        archive.writestr(
            "danger.cmd",
            "cmd.exe powershell",
        )

    outer_archive = (
        tmp_path
        / "outer.zip"
    )

    with zipfile.ZipFile(
        outer_archive,
        "w",
    ) as archive:
        archive.write(
            inner_archive,
            arcname=(
                "archives/"
                "inner.zip"
            ),
        )

    result = (
        ScannerService()
        .scan(
            outer_archive
        )
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert result.target_sha256

    assert any(
        threat.relative_path
        == "archives/inner.zip"
        for threat
        in result.archive_threats
    )

    assert any(
        file_result.relative_path
        == (
            "archives/inner.zip"
            "!/danger.cmd"
        )
        for file_result
        in result.file_results
    )

    assert (
        result.total_files_checked
        == 1
    )

    assert (
        result.total_threats_found
        > 0
    )


def test_scanner_stops_at_maximum_nested_depth(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        AppConfig,
        "MAX_ARCHIVE_DEPTH",
        2,
    )

    level_three = (
        tmp_path
        / "level3.zip"
    )

    with zipfile.ZipFile(
        level_three,
        "w",
    ) as archive:
        archive.writestr(
            "deep.txt",
            "deep content",
        )

    level_two = (
        tmp_path
        / "level2.zip"
    )

    with zipfile.ZipFile(
        level_two,
        "w",
    ) as archive:
        archive.write(
            level_three,
            arcname="level3.zip",
        )

    level_one = (
        tmp_path
        / "level1.zip"
    )

    with zipfile.ZipFile(
        level_one,
        "w",
    ) as archive:
        archive.write(
            level_two,
            arcname="level2.zip",
        )

    result = (
        ScannerService()
        .scan(
            level_one
        )
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert any(
        (
            "Maximum nested "
            "archive depth reached"
        )
        in threat.description
        for threat
        in result.archive_threats
    )

    assert all(
        file_result.relative_path
        != (
            "level2.zip"
            "!/level3.zip"
            "!/deep.txt"
        )
        for file_result
        in result.file_results
    )


def test_scanner_detects_unsafe_archive_path(
    tmp_path: Path,
) -> None:
    archive_path = (
        tmp_path
        / "unsafe.zip"
    )

    with zipfile.ZipFile(
        archive_path,
        "w",
    ) as archive:
        archive.writestr(
            "../outside.txt",
            "danger",
        )

        archive.writestr(
            "safe.txt",
            "safe",
        )

    result = (
        ScannerService()
        .scan(
            archive_path
        )
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert any(
        "Unsafe archive path"
        in threat.description
        for threat
        in result.archive_threats
    )

    assert (
        result.total_files_checked
        == 1
    )

    assert any(
        file_result.relative_path
        == "safe.txt"
        for file_result
        in result.file_results
    )

    assert all(
        file_result.relative_path
        != "../outside.txt"
        for file_result
        in result.file_results
    )


def test_scanner_preserves_archive_member_paths(
    tmp_path: Path,
) -> None:
    archive_path = (
        tmp_path
        / "structure.zip"
    )

    with zipfile.ZipFile(
        archive_path,
        "w",
    ) as archive:
        archive.writestr(
            (
                "folder/"
                "subfolder/"
                "file.txt"
            ),
            "content",
        )

    result = (
        ScannerService()
        .scan(
            archive_path
        )
    )

    assert (
        result.status
        == ScanStatus.COMPLETED
    )

    assert (
        result.total_files_checked
        == 1
    )

    file_result = (
        result.file_results[0]
    )

    assert (
        file_result.relative_path
        == (
            "folder/"
            "subfolder/"
            "file.txt"
        )
    )

    assert (
        "/tmp/"
        not in file_result
        .relative_path
    )

    assert (
        "anti_archive_scanner_"
        not in file_result
        .relative_path
    )


def test_target_sha256_differs_for_different_files(
    tmp_path: Path,
) -> None:
    first_file = (
        tmp_path
        / "first.txt"
    )

    second_file = (
        tmp_path
        / "second.txt"
    )

    first_file.write_text(
        "first",
        encoding="utf-8",
    )

    second_file.write_text(
        "second",
        encoding="utf-8",
    )

    scanner = ScannerService()

    first_result = scanner.scan(
        first_file
    )

    second_result = scanner.scan(
        second_file
    )

    assert (
        first_result.target_sha256
    )

    assert (
        second_result.target_sha256
    )

    assert (
        first_result.target_sha256
        != second_result.target_sha256
    )


def test_temp_manager_creates_directory_inside_configured_root(
    tmp_path: Path,
) -> None:
    temp_root = (
        tmp_path
        / "scanner-temp"
    )

    manager = TempManager(
        root_dir=temp_root,
        prefix=(
            "anti_archive_scanner_"
        ),
    )

    temp_dir = (
        manager.create_temp_dir()
    )

    try:
        assert temp_dir.exists()

        assert (
            temp_dir.parent.resolve()
            == temp_root.resolve()
        )

        assert (
            temp_dir.name.startswith(
                "anti_archive_scanner_"
            )
        )

    finally:
        manager.cleanup(
            temp_dir
        )


def test_temp_manager_context_removes_directory(
    tmp_path: Path,
) -> None:
    manager = TempManager(
        root_dir=(
            tmp_path
            / "temp-root"
        )
    )

    with (
        manager
        .temporary_directory()
    ) as temp_dir:
        assert temp_dir.exists()

        file_path = (
            temp_dir
            / "test.txt"
        )

        file_path.write_text(
            "test",
            encoding="utf-8",
        )

        assert file_path.exists()

    assert (
        not temp_dir.exists()
    )


def test_temp_manager_context_removes_directory_after_error(
    tmp_path: Path,
) -> None:
    manager = TempManager(
        root_dir=(
            tmp_path
            / "temp-root"
        )
    )

    temp_dir: Path | None = None

    with pytest.raises(
        RuntimeError
    ):
        with (
            manager
            .temporary_directory()
        ) as created_dir:
            temp_dir = created_dir

            (
                created_dir
                / "partial.bin"
            ).write_bytes(
                b"partial"
            )

            raise RuntimeError(
                "test failure"
            )

    assert temp_dir is not None

    assert (
        not temp_dir.exists()
    )


def test_temp_manager_refuses_to_delete_unmanaged_directory(
    tmp_path: Path,
) -> None:
    manager = TempManager(
        root_dir=(
            tmp_path
            / "managed"
        )
    )

    unrelated = (
        tmp_path
        / "unrelated"
    )

    unrelated.mkdir()

    with pytest.raises(
        ValueError
    ):
        manager.cleanup(
            unrelated
        )

    assert unrelated.exists()


def test_temp_manager_removes_stale_directory(
    tmp_path: Path,
) -> None:
    temp_root = (
        tmp_path
        / "scanner-temp"
    )

    manager = TempManager(
        root_dir=temp_root,
        prefix=(
            "anti_archive_scanner_"
        ),
        max_age_seconds=10,
    )

    stale_directory = (
        manager.create_temp_dir()
    )

    old_timestamp = (
        time.time()
        - 60
    )

    os.utime(
        stale_directory,
        (
            old_timestamp,
            old_timestamp,
        ),
    )

    removed = (
        manager.cleanup_stale()
    )

    assert removed == 1

    assert (
        not stale_directory.exists()
    )


def test_temp_manager_keeps_recent_directory(
    tmp_path: Path,
) -> None:
    manager = TempManager(
        root_dir=(
            tmp_path
            / "scanner-temp"
        ),
        max_age_seconds=3600,
    )

    recent_directory = (
        manager.create_temp_dir()
    )

    removed = (
        manager.cleanup_stale()
    )

    try:
        assert removed == 0

        assert (
            recent_directory.exists()
        )

    finally:
        manager.cleanup(
            recent_directory
        )