import json
from pathlib import Path

from infrastructure.local_quarantine import (
    LocalQuarantineProvider,
)


def test_file_is_moved_to_local_quarantine(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / "danger.exe"
    source_file.write_bytes(b"MZ test")

    quarantine_dir = tmp_path / "quarantine"

    provider = LocalQuarantineProvider(
        quarantine_dir=quarantine_dir
    )

    result = provider.quarantine(source_file)

    assert result.success is True
    assert not source_file.exists()
    assert result.quarantine_path is not None
    assert result.quarantine_path.exists()
    assert (
        result.quarantine_path.suffix
        == ".quarantine"
    )


def test_quarantine_metadata_is_created(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / "danger.txt"
    source_file.write_text(
        "test",
        encoding="utf-8",
    )

    quarantine_dir = tmp_path / "quarantine"

    result = LocalQuarantineProvider(
        quarantine_dir=quarantine_dir
    ).quarantine(source_file)

    assert result.success

    metadata_files = list(
        quarantine_dir.glob("*.json")
    )

    assert len(metadata_files) == 1

    metadata = json.loads(
        metadata_files[0].read_text(
            encoding="utf-8"
        )
    )

    assert metadata["original_name"] == "danger.txt"
    assert metadata["sha256"]
    assert metadata["stored_name"].endswith(
        ".quarantine"
    )


def test_missing_file_cannot_be_quarantined(
    tmp_path: Path,
) -> None:
    missing_file = tmp_path / "missing.txt"

    provider = LocalQuarantineProvider(
        quarantine_dir=tmp_path / "quarantine"
    )

    result = provider.quarantine(missing_file)

    assert result.success is False
    assert result.quarantine_path is None