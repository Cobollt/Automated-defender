from pathlib import Path

from config import AppConfig
from domain.enums import ThreatType
from domain.models import DetectedThreat
from utils.path_security import (
    build_safe_extract_path,
)


class BaseArchiveReader:
    COPY_CHUNK_SIZE = (
        1024 * 1024
    )

    @staticmethod
    def max_extracted_size() -> int:
        if hasattr(
            AppConfig,
            "max_extracted_size_bytes",
        ):
            return (
                AppConfig
                .max_extracted_size_bytes()
            )

        return (
            AppConfig
            .MAX_EXTRACTED_SIZE_MB
            * 1024
            * 1024
        )

    @staticmethod
    def validate_member_path(
        archive_path: Path,
        destination_dir: Path,
        member_name: str,
    ) -> tuple[
        Path | None,
        DetectedThreat | None,
    ]:
        target_path = (
            build_safe_extract_path(
                base_dir=destination_dir,
                member_name=member_name,
            )
        )

        if target_path is None:
            return (
                None,
                DetectedThreat(
                    threat_type=(
                        ThreatType
                        .UNSAFE_PATH
                    ),
                    description=(
                        "Unsafe archive path: "
                        f"{member_name}"
                    ),
                    score=50,
                    file_path=archive_path,
                ),
            )

        return target_path, None

    @classmethod
    def copy_limited(
        cls,
        source,
        target,
        current_size: int,
    ) -> int:
        written = 0

        while True:
            chunk = source.read(
                cls.COPY_CHUNK_SIZE
            )

            if not chunk:
                break

            written += len(chunk)

            if (
                current_size
                + written
                > cls.max_extracted_size()
            ):
                raise ValueError(
                    "Archive extracted size "
                    "exceeded the configured "
                    "limit"
                )

            target.write(chunk)

        return written

    @staticmethod
    def archive_bomb_threat(
        archive_path: Path,
        description: str,
        score: int = 50,
    ) -> DetectedThreat:
        return DetectedThreat(
            threat_type=(
                ThreatType
                .ARCHIVE_BOMB_RISK
            ),
            description=description,
            score=score,
            file_path=archive_path,
        )