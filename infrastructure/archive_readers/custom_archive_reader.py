from pathlib import Path

from domain.archive_interfaces import ArchiveReaderInterface
from domain.enums import ThreatType
from domain.models import DetectedThreat


class CustomArchiveReader(ArchiveReaderInterface):
    CUSTOM_EXTENSION = ".custom"
    CUSTOM_MAGIC = b"CSTM"

    def supports(self, archive_path: Path) -> bool:
        try:
            with archive_path.open("rb") as file:
                header = file.read(len(self.CUSTOM_MAGIC))
        except OSError:
            return False

        return (
            archive_path.suffix.lower() == self.CUSTOM_EXTENSION
            or header == self.CUSTOM_MAGIC
        )

    def inspect(self, archive_path: Path) -> list[DetectedThreat]:
        return [
            DetectedThreat(
                threat_type=ThreatType.UNSUPPORTED_ARCHIVE,
                description=(
                    "Custom archive format detected, but its binary structure "
                    "has not been configured yet"
                ),
                score=25,
                file_path=archive_path,
            )
        ]

    def extract(
        self,
        archive_path: Path,
        destination_dir: Path,
    ) -> list[Path]:
        raise NotImplementedError(
            "Custom archive extraction requires the format specification"
        )