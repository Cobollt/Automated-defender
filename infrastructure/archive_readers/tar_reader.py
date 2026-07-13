import tarfile
from pathlib import Path

from config import AppConfig
from domain.archive_interfaces import ArchiveReaderInterface
from domain.enums import ThreatType
from domain.models import DetectedThreat
from infrastructure.archive_readers.base_reader import BaseArchiveReader


class TarArchiveReader(BaseArchiveReader, ArchiveReaderInterface):
    EXTENSIONS = {
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
    }

    def supports(self, archive_path: Path) -> bool:
        if archive_path.suffix.lower() in self.EXTENSIONS:
            return tarfile.is_tarfile(archive_path)

        return tarfile.is_tarfile(archive_path)

    def inspect(self, archive_path: Path) -> list[DetectedThreat]:
        threats: list[DetectedThreat] = []

        if not tarfile.is_tarfile(archive_path):
            return [
                DetectedThreat(
                    threat_type=ThreatType.UNKNOWN_FORMAT,
                    description="File is not a valid TAR archive",
                    score=20,
                    file_path=archive_path,
                )
            ]

        with tarfile.open(archive_path, "r:*") as archive:
            members = archive.getmembers()

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
                member.size
                for member in members
                if member.isfile()
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

            for member in members:
                _, path_threat = self.validate_member_path(
                    archive_path=archive_path,
                    destination_dir=Path("/safe-inspection-root"),
                    member_name=member.name,
                )

                if path_threat is not None:
                    threats.append(path_threat)

                if member.issym() or member.islnk():
                    threats.append(
                        DetectedThreat(
                            threat_type=ThreatType.UNSAFE_PATH,
                            description=(
                                f"Archive contains symbolic or hard link: "
                                f"{member.name}"
                            ),
                            score=35,
                            file_path=archive_path,
                        )
                    )

                if member.isdev():
                    threats.append(
                        DetectedThreat(
                            threat_type=ThreatType.UNSAFE_PATH,
                            description=(
                                f"Archive contains device entry: {member.name}"
                            ),
                            score=50,
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

        with tarfile.open(archive_path, "r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue

                target_path, threat = self.validate_member_path(
                    archive_path=archive_path,
                    destination_dir=destination_dir,
                    member_name=member.name,
                )

                if threat is not None or target_path is None:
                    continue

                extracted_count += 1

                if extracted_count > AppConfig.MAX_FILES_IN_ARCHIVE:
                    raise ValueError(
                        "Archive file count exceeded during extraction"
                    )

                source = archive.extractfile(member)

                if source is None:
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)

                with source:
                    with target_path.open("wb") as target:
                        written = self._copy_limited(
                            source=source,
                            target=target,
                            current_size=extracted_size,
                        )

                extracted_size += written
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