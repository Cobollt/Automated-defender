import json
from pathlib import Path

from infrastructure.local_quarantine import LocalQuarantineProvider
from utils.hashing import calculate_sha256


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
    assert result.provider_name == (
        "AntiArchiveScanner Local Quarantine"
    )

    assert not source_file.exists()

    assert result.quarantine_path is not None
    assert result.quarantine_path.exists()

    assert result.quarantine_path.parent == quarantine_dir
    assert result.quarantine_path.suffix == ".quarantine"


def test_quarantine_metadata_is_created(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / "danger.txt"
    source_file.write_text(
        "test",
        encoding="utf-8",
    )

    original_sha256 = calculate_sha256(
        source_file
    )

    quarantine_dir = tmp_path / "quarantine"

    result = LocalQuarantineProvider(
        quarantine_dir=quarantine_dir
    ).quarantine(source_file)

    assert result.success is True
    assert result.quarantine_path is not None

    metadata_files = list(
        quarantine_dir.glob("*.json")
    )

    assert len(metadata_files) == 1

    metadata = json.loads(
        metadata_files[0].read_text(
            encoding="utf-8"
        )
    )

    assert metadata["quarantine_id"]
    assert metadata["original_name"] == "danger.txt"
    assert metadata["original_path"] == str(
        source_file.resolve()
    )

    assert metadata["stored_name"] == (
        result.quarantine_path.name
    )

    assert metadata["sha256"] == original_sha256

    assert metadata["provider"] == (
        "AntiArchiveScanner Local Quarantine"
    )

    assert metadata["quarantined_at"]


def test_quarantined_file_keeps_original_content(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / "danger.bin"
    original_content = (
        b"important suspicious content"
    )

    source_file.write_bytes(
        original_content
    )

    quarantine_dir = tmp_path / "quarantine"

    result = LocalQuarantineProvider(
        quarantine_dir=quarantine_dir
    ).quarantine(source_file)

    assert result.success is True
    assert result.quarantine_path is not None

    assert result.quarantine_path.read_bytes() == (
        original_content
    )


def test_original_extension_is_removed(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / "danger.exe"
    source_file.write_bytes(b"MZ test")

    quarantine_dir = tmp_path / "quarantine"

    result = LocalQuarantineProvider(
        quarantine_dir=quarantine_dir
    ).quarantine(source_file)

    assert result.success is True
    assert result.quarantine_path is not None

    assert result.quarantine_path.suffix == (
        ".quarantine"
    )

    assert ".exe" not in (
        result.quarantine_path.name
    )


def test_missing_file_cannot_be_quarantined(
    tmp_path: Path,
) -> None:
    missing_file = tmp_path / "missing.txt"

    provider = LocalQuarantineProvider(
        quarantine_dir=tmp_path / "quarantine"
    )

    result = provider.quarantine(
        missing_file
    )

    assert result.success is False
    assert result.quarantine_path is None
    assert "не существует" in (
        result.message or ""
    ).lower()


def test_directory_cannot_be_quarantined(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "folder"
    directory.mkdir()

    provider = LocalQuarantineProvider(
        quarantine_dir=tmp_path / "quarantine"
    )

    result = provider.quarantine(
        directory
    )

    assert result.success is False
    assert result.quarantine_path is None
    assert directory.exists()

    assert "только обычные файлы" in (
        result.message or ""
    ).lower()


def test_quarantine_directory_is_created_automatically(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / "danger.txt"
    source_file.write_text(
        "test",
        encoding="utf-8",
    )

    quarantine_dir = (
        tmp_path
        / "nested"
        / "quarantine"
    )

    assert not quarantine_dir.exists()

    result = LocalQuarantineProvider(
        quarantine_dir=quarantine_dir
    ).quarantine(source_file)

    assert result.success is True
    assert quarantine_dir.exists()


def test_quarantined_file_permissions_are_restricted(
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

    assert result.success is True
    assert result.quarantine_path is not None

    permissions = (
        result.quarantine_path.stat().st_mode
        & 0o777
    )

    assert permissions == 0o600


def test_metadata_and_quarantined_file_have_same_identifier(
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

    assert result.success is True
    assert result.quarantine_path is not None

    metadata_path = next(
        quarantine_dir.glob("*.json")
    )

    quarantine_identifier = (
        result.quarantine_path.stem
    )

    metadata_identifier = (
        metadata_path.stem
    )

    assert (
        quarantine_identifier
        == metadata_identifier
    )


def test_rollback_restores_file_when_metadata_write_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_file = tmp_path / "danger.txt"
    original_content = b"restore me"

    source_file.write_bytes(
        original_content
    )

    quarantine_dir = tmp_path / "quarantine"

    original_write_text = Path.write_text

    def failing_write_text(
        self,
        *args,
        **kwargs,
    ):
        if self.suffix == ".json":
            raise OSError(
                "Simulated metadata write failure"
            )

        return original_write_text(
            self,
            *args,
            **kwargs,
        )

    monkeypatch.setattr(
        Path,
        "write_text",
        failing_write_text,
    )

    provider = LocalQuarantineProvider(
        quarantine_dir=quarantine_dir
    )

    result = provider.quarantine(
        source_file
    )

    assert result.success is False

    assert source_file.exists()
    assert source_file.read_bytes() == (
        original_content
    )

    quarantine_files = list(
        quarantine_dir.glob("*.quarantine")
    )

    assert quarantine_files == []


def test_sha256_matches_quarantined_content(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / "danger.dat"
    source_file.write_bytes(
        b"hash verification content"
    )

    quarantine_dir = tmp_path / "quarantine"

    result = LocalQuarantineProvider(
        quarantine_dir=quarantine_dir
    ).quarantine(source_file)

    assert result.success is True
    assert result.quarantine_path is not None

    metadata_path = next(
        quarantine_dir.glob("*.json")
    )

    metadata = json.loads(
        metadata_path.read_text(
            encoding="utf-8"
        )
    )

    quarantined_sha256 = calculate_sha256(
        result.quarantine_path
    )

    assert metadata["sha256"] == (
        quarantined_sha256
    )