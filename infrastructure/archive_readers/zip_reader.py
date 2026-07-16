import zipfile
from pathlib import Path

from config import AppConfig
from domain.archive_interfaces import ArchiveReaderInterface
from domain.enums import ThreatType
from domain.models import DetectedThreat
from infrastructure.archive_readers.base_reader import BaseArchiveReader


class ZipArchiveReader(BaseArchiveReader, ArchiveReaderInterface):
    MAGIC_SIGNATURES = (
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
    )

    def supports(self, archive_path: Path) -> bool:
        try:
            with archive_path.open("rb") as file:
                header = file.read(4)
        except OSError:
            return False

        return (
            archive_path.suffix.lower() == ".zip"
            or header.startswith(self.MAGIC_SIGNATURES)
        )

    def inspect(self, archive_path: Path) -> list[DetectedThreat]:
        threats: list[DetectedThreat] = []

        if not zipfile.is_zipfile(archive_path):
            return [
                DetectedThreat(
                    threat_type=ThreatType.UNKNOWN_FORMAT,
                    description="File has a ZIP-like extension but is not a valid ZIP archive",
                    score=20,
                    file_path=archive_path,
                )
            ]

        with zipfile.ZipFile(archive_path, "r") as archive:
            members = archive.infolist()

            if len(members) > AppConfig.MAX_FILES_IN_ARCHIVE:
                threats.append(
                    DetectedThreat(
                        threat_type=ThreatType.ARCHIVE_BOMB_RISK,
                        description=(
                            f"Archive contains too many entries: {len(members)}"
                        ),
                        score=40,
                        file_path=archive_path,
                    )
                )

            total_size = sum(
                member.file_size
                for member in members
                if not member.is_dir()
            )

            if total_size > self.max_extracted_size():
                threats.append(
                    DetectedThreat(
                        threat_type=ThreatType.ARCHIVE_BOMB_RISK,
                        description=(
                            "Declared extracted size exceeds limit: "
                            f"{total_size} bytes"
                        ),
                        score=50,
                        file_path=archive_path,
                    )
                )

            compressed_size = sum(
                member.compress_size
                for member in members
                if not member.is_dir()
            )

            if compressed_size > 0:
                compression_ratio = total_size / compressed_size

                if compression_ratio > AppConfig.MAX_COMPRESSION_RATIO:
                    threats.append(
                        DetectedThreat(
                            threat_type=ThreatType.ARCHIVE_BOMB_RISK,
                            description=(
                                "Suspicious compression ratio: "
                                f"{compression_ratio:.2f}"
                            ),
                            score=40,
                            file_path=archive_path,
                        )
                    )

            for member in members:
                _, path_threat = self.validate_member_path(
                    archive_path=archive_path,
                    destination_dir=Path("/safe-inspection-root"),
                    member_name=member.filename,
                )

                if path_threat is not None:
                    threats.append(path_threat)

                if member.flag_bits & 0x1:
                    threats.append(
                        DetectedThreat(
                            threat_type=ThreatType.ENCRYPTED_ARCHIVE,
                            description=(
                                f"Encrypted archive entry: {member.filename}"
                            ),
                            score=25,
                            file_path=archive_path,
                        )
                    )

        return threats

    def extract(
        self,
        archive_path: Path,
        destination_dir: Path,
    ) -> list[Path]:
        extracted_files: list[Path] = []
        extracted_size = 0
        extracted_count = 0

        with zipfile.ZipFile(archive_path, "r") as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue

                target_path, threat = self.validate_member_path(
                    archive_path=archive_path,
                    destination_dir=destination_dir,
                    member_name=member.filename,
                )

                if threat is not None or target_path is None:
                    continue

                extracted_count += 1

                if extracted_count > AppConfig.MAX_FILES_IN_ARCHIVE:
                    raise ValueError(
                        "Archive file count exceeded during extraction"
                    )

                if member.flag_bits & 0x1:
                    raise ValueError(
                        f"Encrypted ZIP entry is not supported: {member.filename}"
                    )

                target_path.parent.mkdir(parents=True, exist_ok=True)

                with archive.open(member, "r") as source:
                    with target_path.open("wb") as target:
                        extracted_size += self._copy_limited(
                            source=source,
                            target=target,
                            current_size=extracted_size,
                        )

                extracted_files.append(target_path)

        return extracted_files

    def _copy_limited(
        self,
        source,
        target,
        current_size: int,
    ) -> int:
        written = 0
        chunk_size = 1024 * 1024

        while True:
            chunk = source.read(chunk_size)

            if not chunk:
                break

            written += len(chunk)

            if current_size + written > self.max_extracted_size():
                raise ValueError(
                    "Archive extracted size exceeded the configured limit"
                )

            target.write(chunk)

        return written