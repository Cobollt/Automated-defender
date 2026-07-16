from pathlib import Path

from application.risk_evaluator import RiskEvaluator
from config import AppConfig
from domain.enums import ScanStatus, ThreatType
from domain.models import DetectedThreat, ScanResult
from infrastructure.archive_detector import ArchiveDetector
from infrastructure.archive_readers.custom_archive_reader import (
    CustomArchiveReader,
)
from infrastructure.archive_readers.tar_reader import TarArchiveReader
from infrastructure.archive_readers.zip_reader import ZipArchiveReader
from infrastructure.file_analyzer import FileAnalyzer
from infrastructure.safe_extractor import SafeExtractor
from infrastructure.temp_manager import TempManager
from utils.hashing import calculate_sha256


class ScannerService:
    def __init__(
        self,
        archive_detector: ArchiveDetector | None = None,
        file_analyzer: FileAnalyzer | None = None,
        safe_extractor: SafeExtractor | None = None,
        temp_manager: TempManager | None = None,
        risk_evaluator: RiskEvaluator | None = None,
    ) -> None:
        self.risk_evaluator = risk_evaluator or RiskEvaluator()

        self.archive_detector = archive_detector or ArchiveDetector(
            [
                ZipArchiveReader(),
                TarArchiveReader(),
                CustomArchiveReader(),
            ]
        )

        self.file_analyzer = file_analyzer or FileAnalyzer(
            self.risk_evaluator
        )

        self.safe_extractor = safe_extractor or SafeExtractor(
            self.archive_detector
        )

        self.temp_manager = temp_manager or TempManager()

    def scan(self, target_path: Path) -> ScanResult:
        result = ScanResult(
            target_path=target_path,
            status=ScanStatus.SCANNING,
        )

        if not target_path.exists() or not target_path.is_file():
            result.fail(
                "File does not exist or is not a regular file: "
                f"{target_path}"
            )
            return result

        try:
            result.target_sha256 = calculate_sha256(target_path)

            if self.archive_detector.is_archive(target_path):
                self._scan_archive(
                    archive_path=target_path,
                    result=result,
                    archive_prefix="",
                )
            else:
                self._scan_single_file(
                    file_path=target_path,
                    result=result,
                    relative_path=target_path.name,
                )

            self._finalize_result(result)
            result.complete()

        except Exception as error:
            result.fail(str(error))

        return result

    def _scan_single_file(
        self,
        file_path: Path,
        result: ScanResult,
        relative_path: str | None,
    ) -> None:
        file_result = self.file_analyzer.analyze(
            file_path,
            relative_path=relative_path,
        )

        result.file_results.append(file_result)
        result.total_files_checked += 1

    def _scan_archive(
        self,
        archive_path: Path,
        result: ScanResult,
        depth: int = 0,
        archive_prefix: str = "",
    ) -> None:
        if depth >= AppConfig.MAX_ARCHIVE_DEPTH:
            result.archive_threats.append(
                DetectedThreat(
                    threat_type=ThreatType.NESTED_ARCHIVE,
                    description=(
                        "Maximum nested archive depth reached: "
                        f"{AppConfig.MAX_ARCHIVE_DEPTH}"
                    ),
                    score=35,
                    file_path=archive_path,
                    relative_path=(
                        archive_prefix or archive_path.name
                    ),
                )
            )
            return

        archive_threats = self.safe_extractor.inspect_archive(
            archive_path
        )

        for threat in archive_threats:
            if threat.relative_path is None:
                threat.relative_path = (
                    archive_prefix or archive_path.name
                )

            result.archive_threats.append(threat)

        temp_dir = self.temp_manager.create_temp_dir()

        try:
            extracted_files = self.safe_extractor.extract(
                archive_path,
                temp_dir,
            )

            for extracted_file in extracted_files:
                member_path = extracted_file.relative_to(
                    temp_dir
                ).as_posix()

                if archive_prefix:
                    relative_path = (
                        f"{archive_prefix}!/{member_path}"
                    )
                else:
                    relative_path = member_path

                if self.archive_detector.is_archive(
                    extracted_file
                ):
                    result.archive_threats.append(
                        DetectedThreat(
                            threat_type=ThreatType.NESTED_ARCHIVE,
                            description=(
                                "Nested archive detected at "
                                f"depth {depth + 1}: "
                                f"{relative_path}"
                            ),
                            score=10,
                            file_path=extracted_file,
                            relative_path=relative_path,
                        )
                    )

                    self._scan_archive(
                        archive_path=extracted_file,
                        result=result,
                        depth=depth + 1,
                        archive_prefix=relative_path,
                    )
                else:
                    self._scan_single_file(
                        file_path=extracted_file,
                        result=result,
                        relative_path=relative_path,
                    )

        finally:
            self.temp_manager.cleanup(temp_dir)

    def _finalize_result(
        self,
        result: ScanResult,
    ) -> None:
        file_threats_count = sum(
            len(file_result.threats)
            for file_result in result.file_results
        )

        result.total_threats_found = (
            file_threats_count
            + len(result.archive_threats)
        )

        result.risk_score = (
            self.risk_evaluator.calculate_scan_score(
                file_results=result.file_results,
                archive_threats=result.archive_threats,
            )
        )

        result.risk_level = (
            self.risk_evaluator.calculate_level(
                result.risk_score
            )
        )