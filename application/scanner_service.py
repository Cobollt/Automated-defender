from pathlib import Path

from application.risk_evaluator import (
    RiskEvaluator,
)
from config import AppConfig
from domain.enums import (
    ScanStatus,
    ThreatType,
)
from domain.models import (
    DetectedThreat,
    ScanResult,
)
from infrastructure.archive_detector import (
    ArchiveDetector,
)
from infrastructure.archive_readers.custom_archive_reader import (
    CustomArchiveReader,
)
from infrastructure.archive_readers.tar_reader import (
    TarArchiveReader,
)
from infrastructure.archive_readers.zip_reader import (
    ZipArchiveReader,
)
from infrastructure.file_analyzer import (
    FileAnalyzer,
)
from infrastructure.safe_extractor import (
    SafeExtractor,
)
from infrastructure.temp_manager import (
    TempManager,
)
from utils.hashing import (
    calculate_sha256,
)


class ScannerService:
    BLOCKING_ARCHIVE_THREAT_TYPES = {
        ThreatType.UNSUPPORTED_ARCHIVE,
        ThreatType.ENCRYPTED_ARCHIVE,
        ThreatType.ARCHIVE_BOMB_RISK,
        ThreatType.UNKNOWN_FORMAT,
    }

    def __init__(
        self,
        archive_detector: (
            ArchiveDetector | None
        ) = None,
        file_analyzer: (
            FileAnalyzer | None
        ) = None,
        safe_extractor: (
            SafeExtractor | None
        ) = None,
        temp_manager: (
            TempManager | None
        ) = None,
        risk_evaluator: (
            RiskEvaluator | None
        ) = None,
    ) -> None:
        self.risk_evaluator = (
            risk_evaluator
            or RiskEvaluator()
        )

        self.archive_detector = (
            archive_detector
            or ArchiveDetector(
                [
                    ZipArchiveReader(),
                    TarArchiveReader(),
                    CustomArchiveReader(),
                ]
            )
        )

        self.file_analyzer = (
            file_analyzer
            or FileAnalyzer(
                self.risk_evaluator
            )
        )

        self.safe_extractor = (
            safe_extractor
            or SafeExtractor(
                self.archive_detector
            )
        )

        self.temp_manager = (
            temp_manager
            or TempManager()
        )

        self._cleanup_stale_temp_dirs()

    def scan(
        self,
        target_path: Path,
    ) -> ScanResult:
        target_path = Path(
            target_path
        ).resolve()

        result = ScanResult(
            target_path=target_path,
            status=ScanStatus.SCANNING,
        )

        if not target_path.exists():
            result.fail(
                "File does not exist: "
                f"{target_path}"
            )

            return result

        if not target_path.is_file():
            result.fail(
                "Path is not a regular "
                "file: "
                f"{target_path}"
            )

            return result

        try:
            self._validate_input_file_size(
                target_path
            )

            result.target_sha256 = (
                calculate_sha256(
                    target_path
                )
            )

            reader = (
                self.archive_detector
                .get_reader(
                    target_path
                )
            )

            if reader is not None:
                self._scan_archive(
                    archive_path=(
                        target_path
                    ),
                    result=result,
                    depth=0,
                    archive_prefix="",
                )

            else:
                unhandled_archive = (
                    self.archive_detector
                    .get_unhandled_archive_threat(
                        file_path=(
                            target_path
                        ),
                        relative_path=(
                            target_path.name
                        ),
                    )
                )

                if (
                    unhandled_archive
                    is not None
                ):
                    result.archive_threats.append(
                        unhandled_archive
                    )

                else:
                    self._scan_single_file(
                        file_path=(
                            target_path
                        ),
                        result=result,
                        relative_path=(
                            target_path.name
                        ),
                    )

            self._finalize_result(
                result
            )

            result.complete()

        except Exception as error:
            result.fail(
                str(error)
            )

        return result

    def _scan_single_file(
        self,
        file_path: Path,
        result: ScanResult,
        relative_path: (
            str | None
        ),
    ) -> None:
        file_result = (
            self.file_analyzer
            .analyze(
                file_path,
                relative_path=(
                    relative_path
                ),
            )
        )

        result.file_results.append(
            file_result
        )

        result.total_files_checked += 1

    def _scan_archive(
        self,
        archive_path: Path,
        result: ScanResult,
        depth: int = 0,
        archive_prefix: str = "",
    ) -> None:
        relative_archive_path = (
            archive_prefix
            or archive_path.name
        )

        if (
            depth
            >= AppConfig
            .MAX_ARCHIVE_DEPTH
        ):
            result.archive_threats.append(
                DetectedThreat(
                    threat_type=(
                        ThreatType
                        .NESTED_ARCHIVE
                    ),
                    description=(
                        "Maximum nested "
                        "archive depth "
                        "reached: "
                        f"{AppConfig.MAX_ARCHIVE_DEPTH}"
                    ),
                    score=35,
                    file_path=(
                        archive_path
                    ),
                    relative_path=(
                        relative_archive_path
                    ),
                )
            )

            return

        archive_threats = (
            self.safe_extractor
            .inspect_archive(
                archive_path
            )
        )

        for threat in (
            archive_threats
        ):
            if (
                threat.relative_path
                is None
            ):
                threat.relative_path = (
                    relative_archive_path
                )

            result.archive_threats.append(
                threat
            )

        if self._contains_blocking_archive_threat(
            archive_threats
        ):
            return

        with (
            self.temp_manager
            .temporary_directory()
        ) as temp_dir:
            extracted_files = (
                self.safe_extractor
                .extract(
                    archive_path,
                    temp_dir,
                )
            )

            temp_root = (
                temp_dir.resolve()
            )

            for extracted_file in (
                extracted_files
            ):
                extracted_file = (
                    extracted_file.resolve()
                )

                try:
                    member_path = (
                        extracted_file
                        .relative_to(
                            temp_root
                        )
                        .as_posix()
                    )

                except ValueError:
                    result.archive_threats.append(
                        DetectedThreat(
                            threat_type=(
                                ThreatType
                                .UNSAFE_PATH
                            ),
                            description=(
                                "Extracted file "
                                "resolved outside "
                                "the temporary "
                                "archive directory."
                            ),
                            score=60,
                            file_path=(
                                extracted_file
                            ),
                            relative_path=(
                                relative_archive_path
                            ),
                        )
                    )

                    continue

                if archive_prefix:
                    relative_path = (
                        f"{archive_prefix}"
                        f"!/{member_path}"
                    )

                else:
                    relative_path = (
                        member_path
                    )

                reader = (
                    self.archive_detector
                    .get_reader(
                        extracted_file
                    )
                )

                if reader is not None:
                    result.archive_threats.append(
                        DetectedThreat(
                            threat_type=(
                                ThreatType
                                .NESTED_ARCHIVE
                            ),
                            description=(
                                "Nested archive "
                                "detected at "
                                f"depth "
                                f"{depth + 1}: "
                                f"{relative_path}"
                            ),
                            score=10,
                            file_path=(
                                extracted_file
                            ),
                            relative_path=(
                                relative_path
                            ),
                        )
                    )

                    self._scan_archive(
                        archive_path=(
                            extracted_file
                        ),
                        result=result,
                        depth=depth + 1,
                        archive_prefix=(
                            relative_path
                        ),
                    )

                    continue

                unhandled_archive = (
                    self.archive_detector
                    .get_unhandled_archive_threat(
                        file_path=(
                            extracted_file
                        ),
                        relative_path=(
                            relative_path
                        ),
                    )
                )

                if (
                    unhandled_archive
                    is not None
                ):
                    result.archive_threats.append(
                        DetectedThreat(
                            threat_type=(
                                ThreatType
                                .NESTED_ARCHIVE
                            ),
                            description=(
                                "Nested archive "
                                "detected but its "
                                "format cannot be "
                                "safely extracted: "
                                f"{relative_path}"
                            ),
                            score=10,
                            file_path=(
                                extracted_file
                            ),
                            relative_path=(
                                relative_path
                            ),
                        )
                    )

                    result.archive_threats.append(
                        unhandled_archive
                    )

                    continue

                self._scan_single_file(
                    file_path=(
                        extracted_file
                    ),
                    result=result,
                    relative_path=(
                        relative_path
                    ),
                )

    def _contains_blocking_archive_threat(
        self,
        threats: list[
            DetectedThreat
        ],
    ) -> bool:
        return any(
            threat.threat_type
            in (
                self
                .BLOCKING_ARCHIVE_THREAT_TYPES
            )
            for threat in threats
        )

    def _validate_input_file_size(
        self,
        file_path: Path,
    ) -> None:
        try:
            file_size = (
                file_path
                .stat()
                .st_size
            )

        except OSError as error:
            raise ValueError(
                "Unable to determine "
                "file size: "
                f"{file_path}"
            ) from error

        maximum_size = (
            AppConfig
            .max_input_file_size_bytes()
        )

        if (
            file_size
            > maximum_size
        ):
            raise ValueError(
                "Input file exceeds "
                "maximum allowed size: "
                f"{file_size} bytes. "
                "Maximum: "
                f"{maximum_size} bytes."
            )

    def _cleanup_stale_temp_dirs(
        self,
    ) -> None:
        try:
            self.temp_manager.cleanup_stale()

        except OSError:
            pass

    def _finalize_result(
        self,
        result: ScanResult,
    ) -> None:
        file_threats_count = sum(
            len(
                file_result.threats
            )
            for file_result
            in result.file_results
        )

        result.total_threats_found = (
            file_threats_count
            + len(
                result.archive_threats
            )
        )

        result.risk_score = (
            self.risk_evaluator
            .calculate_scan_score(
                file_results=(
                    result.file_results
                ),
                archive_threats=(
                    result.archive_threats
                ),
            )
        )

        result.risk_level = (
            self.risk_evaluator
            .calculate_level(
                result.risk_score
            )
        )