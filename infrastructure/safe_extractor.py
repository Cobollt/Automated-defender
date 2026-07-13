from pathlib import Path

from domain.archive_interfaces import ArchiveReaderInterface
from domain.models import DetectedThreat
from infrastructure.archive_detector import ArchiveDetector


class SafeExtractor:
    def __init__(self, archive_detector: ArchiveDetector) -> None:
        self._archive_detector = archive_detector

    def inspect_archive(
        self,
        archive_path: Path,
    ) -> list[DetectedThreat]:
        reader = self._get_reader(archive_path)
        return reader.inspect(archive_path)

    def extract(
        self,
        archive_path: Path,
        destination_dir: Path,
    ) -> list[Path]:
        reader = self._get_reader(archive_path)

        destination_dir.mkdir(parents=True, exist_ok=True)

        return reader.extract(
            archive_path=archive_path,
            destination_dir=destination_dir,
        )

    def _get_reader(
        self,
        archive_path: Path,
    ) -> ArchiveReaderInterface:
        reader = self._archive_detector.get_reader(archive_path)

        if reader is None:
            raise ValueError(
                f"Unsupported archive format: {archive_path.name}"
            )

        return reader