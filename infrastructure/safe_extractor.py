from pathlib import Path

from domain.archive_interfaces import (
    ArchiveReaderInterface,
)
from domain.models import DetectedThreat
from infrastructure.archive_detector import (
    ArchiveDetector,
)


class SafeExtractor:
    def __init__(
        self,
        archive_detector: ArchiveDetector,
    ) -> None:
        self._archive_detector = (
            archive_detector
        )

    def inspect_archive(
        self,
        archive_path: Path,
    ) -> list[DetectedThreat]:
        archive_path = (
            archive_path.resolve()
        )

        self._validate_archive_path(
            archive_path
        )

        reader = self._get_reader(
            archive_path
        )

        return reader.inspect(
            archive_path
        )

    def extract(
        self,
        archive_path: Path,
        destination_dir: Path,
    ) -> list[Path]:
        archive_path = (
            archive_path.resolve()
        )

        destination_dir = (
            destination_dir.resolve()
        )

        self._validate_archive_path(
            archive_path
        )

        self._prepare_destination(
            destination_dir
        )

        reader = self._get_reader(
            archive_path
        )

        return reader.extract(
            archive_path=archive_path,
            destination_dir=destination_dir,
        )

    def _get_reader(
        self,
        archive_path: Path,
    ) -> ArchiveReaderInterface:
        reader = (
            self._archive_detector
            .get_reader(
                archive_path
            )
        )

        if reader is None:
            raise ValueError(
                "Unsupported archive "
                "format: "
                f"{archive_path.name}"
            )

        return reader

    @staticmethod
    def _validate_archive_path(
        archive_path: Path,
    ) -> None:
        if not archive_path.exists():
            raise FileNotFoundError(
                "Archive does not exist: "
                f"{archive_path}"
            )

        if not archive_path.is_file():
            raise ValueError(
                "Archive path is not "
                "a file: "
                f"{archive_path}"
            )

    @staticmethod
    def _prepare_destination(
        destination_dir: Path,
    ) -> None:
        if (
            destination_dir.exists()
            and destination_dir.is_symlink()
        ):
            raise ValueError(
                "Extraction destination "
                "cannot be a symbolic link"
            )

        destination_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not destination_dir.is_dir():
            raise NotADirectoryError(
                "Extraction destination "
                "is not a directory: "
                f"{destination_dir}"
            )