from pathlib import Path

from config import AppConfig
from domain.enums import ThreatType
from domain.models import DetectedThreat
from utils.path_security import is_safe_extract_path


class BaseArchiveReader:
    @staticmethod
    def max_extracted_size() -> int:
        return AppConfig.MAX_EXTRACTED_SIZE_MB * 1024 * 1024

    @staticmethod
    def validate_member_path(
        archive_path: Path,
        destination_dir: Path,
        member_name: str,
    ) -> tuple[Path | None, DetectedThreat | None]:
        member_path = Path(member_name)
        target_path = destination_dir / member_path

        if member_path.is_absolute() or ".." in member_path.parts:
            return None, DetectedThreat(
                threat_type=ThreatType.UNSAFE_PATH,
                description=f"Unsafe archive path: {member_name}",
                score=50,
                file_path=archive_path,
            )

        if not is_safe_extract_path(destination_dir, target_path):
            return None, DetectedThreat(
                threat_type=ThreatType.UNSAFE_PATH,
                description=f"Archive path escapes extraction directory: {member_name}",
                score=50,
                file_path=archive_path,
            )

        return target_path, None