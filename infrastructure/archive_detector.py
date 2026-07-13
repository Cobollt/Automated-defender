from pathlib import Path

from domain.archive_interfaces import ArchiveReaderInterface


class ArchiveDetector:
    def __init__(
        self,
        readers: list[ArchiveReaderInterface],
    ) -> None:
        self._readers = readers

    def is_archive(self, file_path: Path) -> bool:
        return self.get_reader(file_path) is not None

    def get_reader(
        self,
        file_path: Path,
    ) -> ArchiveReaderInterface | None:
        for reader in self._readers:
            try:
                if reader.supports(file_path):
                    return reader
            except (OSError, ValueError):
                continue

        return None