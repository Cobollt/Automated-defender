import tarfile
import zipfile
from pathlib import Path
from typing import List

from config import AppConfig
from domain.enums import ThreatType
from domain.models import DetectedThreat
from utils.path_security import is_safe_extract_path


class SafeExtractor:
    def extract(self, archive_path: Path, destination_dir: Path) -> List[Path]:
        suffix = archive_path.suffix.lower()

        if suffix == ".zip":
            return self._extract_zip(archive_path, destination_dir)

        if suffix in {".tar", ".gz", ".tgz", ".bz2", ".xz"}:
            return self._extract_tar(archive_path, destination_dir)

        raise ValueError("Unsupported archive format: {}".format(suffix))

    def inspect_archive(self, archive_path: Path) -> List[DetectedThreat]:
        suffix = archive_path.suffix.lower()

        if suffix == ".zip":
            return self._inspect_zip(archive_path)

        if suffix in {".tar", ".gz", ".tgz", ".bz2", ".xz"}:
            return self._inspect_tar(archive_path)

        return [
            DetectedThreat(
                threat_type=ThreatType.UNKNOWN_FORMAT,
                description="Unsupported archive format: {}".format(suffix),
                score=10,
                file_path=archive_path,
            )
        ]

    def _inspect_zip(self, archive_path: Path) -> List[DetectedThreat]:
        threats: List[DetectedThreat] = []

        with zipfile.ZipFile(archive_path, "r") as archive:
            members = archive.infolist()

            if len(members) > AppConfig.MAX_FILES_IN_ARCHIVE:
                threats.append(
                    DetectedThreat(
                        threat_type=ThreatType.ARCHIVE_BOMB_RISK,
                        description="Too many files in archive: {}".format(len(members)),
                        score=40,
                        file_path=archive_path,
                    )
                )

            total_size = sum(member.file_size for member in members)
            max_size = AppConfig.MAX_EXTRACTED_SIZE_MB * 1024 * 1024

            if total_size > max_size:
                threats.append(
                    DetectedThreat(
                        threat_type=ThreatType.ARCHIVE_BOMB_RISK,
                        description="Archive extracted size is too large: {} bytes".format(total_size),
                        score=40,
                        file_path=archive_path,
                    )
                )

            for member in members:
                member_path = Path(member.filename)

                if member_path.is_absolute() or ".." in member_path.parts:
                    threats.append(
                        DetectedThreat(
                            threat_type=ThreatType.UNSAFE_PATH,
                            description="Unsafe archive path: {}".format(member.filename),
                            score=50,
                            file_path=archive_path,
                        )
                    )

        return threats

    def _inspect_tar(self, archive_path: Path) -> List[DetectedThreat]:
        threats: List[DetectedThreat] = []

        with tarfile.open(archive_path, "r:*") as archive:
            members = archive.getmembers()

            if len(members) > AppConfig.MAX_FILES_IN_ARCHIVE:
                threats.append(
                    DetectedThreat(
                        threat_type=ThreatType.ARCHIVE_BOMB_RISK,
                        description="Too many files in archive: {}".format(len(members)),
                        score=40,
                        file_path=archive_path,
                    )
                )

            total_size = sum(member.size for member in members)
            max_size = AppConfig.MAX_EXTRACTED_SIZE_MB * 1024 * 1024

            if total_size > max_size:
                threats.append(
                    DetectedThreat(
                        threat_type=ThreatType.ARCHIVE_BOMB_RISK,
                        description="Archive extracted size is too large: {} bytes".format(total_size),
                        score=40,
                        file_path=archive_path,
                    )
                )

            for member in members:
                member_path = Path(member.name)

                if member_path.is_absolute() or ".." in member_path.parts:
                    threats.append(
                        DetectedThreat(
                            threat_type=ThreatType.UNSAFE_PATH,
                            description="Unsafe archive path: {}".format(member.name),
                            score=50,
                            file_path=archive_path,
                        )
                    )

                if member.issym() or member.islnk():
                    threats.append(
                        DetectedThreat(
                            threat_type=ThreatType.UNSAFE_PATH,
                            description="Archive contains link: {}".format(member.name),
                            score=30,
                            file_path=archive_path,
                        )
                    )

        return threats

    def _extract_zip(self, archive_path: Path, destination_dir: Path) -> List[Path]:
        extracted_files: List[Path] = []

        with zipfile.ZipFile(archive_path, "r") as archive:
            for member in archive.infolist():
                target_path = destination_dir / member.filename

                if not is_safe_extract_path(destination_dir, target_path):
                    continue

                if member.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)

                with archive.open(member, "r") as source:
                    with target_path.open("wb") as target:
                        target.write(source.read())

                extracted_files.append(target_path)

        return extracted_files

    def _extract_tar(self, archive_path: Path, destination_dir: Path) -> List[Path]:
        extracted_files: List[Path] = []

        with tarfile.open(archive_path, "r:*") as archive:
            for member in archive.getmembers():
                target_path = destination_dir / member.name

                if not is_safe_extract_path(destination_dir, target_path):
                    continue

                if member.isdir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                if not member.isfile():
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)

                source = archive.extractfile(member)

                if source is None:
                    continue

                with source:
                    with target_path.open("wb") as target:
                        target.write(source.read())

                extracted_files.append(target_path)

        return extracted_files