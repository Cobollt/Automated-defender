from pathlib import Path

from domain.enums import ScanStatus
from domain.models import ScanResult
from infrastructure.archive_detector import ArchiveDetector
from infrastructure.archive_readers.custom_archive_reader import (
    CustomArchiveReader,
)
from infrastructure.archive_readers.tar_reader import TarArchiveReader
from infrastructure.archive_readers.zip_reader import ZipArchiveReader
from infrastructure.file_analyzer import FileAnalyzer
from infrastructure.safe_extractor import SafeExtractor
from infrastructure.temp_manager import TempManager


class ScannerService:
    def __init__(self) -> None:
        readers = [
            ZipArchiveReader(),
            TarArchiveReader(),
            CustomArchiveReader(),
        ]

        self.archive_detector = ArchiveDetector(readers)
        self.file_analyzer = FileAnalyzer()
        self.safe_extractor = SafeExtractor(self.archive_detector)
        self.temp_manager = TempManager()

    def scan(self, target_path: Path) -> ScanResult:
        result = ScanResult(
            target_path=target_path,
            status=ScanStatus.SCANNING
        )

        if not target_path.exists():
            result.fail(f"File does not exist: {target_path}")
            return result

        try:
            if self.archive_detector.is_archive(target_path):
                self._scan_archive(target_path, result)
            else:
                self._scan_single_file(target_path, result)

            self._finalize_result(result)
            result.complete()

        except Exception as error:
            result.fail(str(error))

        return result

    def _scan_single_file(self, file_path: Path, result: ScanResult) -> None:
        file_result = self.file_analyzer.analyze(file_path)
        result.file_results.append(file_result)
        result.total_files_checked += 1

    def _scan_archive(
            self,
            archive_path: Path,
            result: ScanResult,
            depth: int = 0,
    ) -> None:
        from config import AppConfig
        from domain.enums import ThreatType
        from domain.models import DetectedThreat

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
                )
            )
            return

        archive_threats = self.safe_extractor.inspect_archive(archive_path)
        result.archive_threats.extend(archive_threats)

        temp_dir = self.temp_manager.create_temp_dir()

        try:
            extracted_files = self.safe_extractor.extract(
                archive_path,
                temp_dir,
            )

            for extracted_file in extracted_files:
                if self.archive_detector.is_archive(extracted_file):
                    result.archive_threats.append(
                        DetectedThreat(
                            threat_type=ThreatType.NESTED_ARCHIVE,
                            description=(
                                f"Nested archive detected at depth {depth + 1}: "
                                f"{extracted_file.name}"
                            ),
                            score=10,
                            file_path=extracted_file,
                        )
                    )

                    self._scan_archive(
                        archive_path=extracted_file,
                        result=result,
                        depth=depth + 1,
                    )
                    continue

                self._scan_single_file(extracted_file, result)

        finally:
            self.temp_manager.cleanup(temp_dir)

    def _finalize_result(self, result: ScanResult) -> None:
        file_threats_count = sum(
            len(file_result.threats)
            for file_result in result.file_results
        )

        result.total_threats_found = (
                file_threats_count
                + len(result.archive_threats)
        )

        scores = [
            file_result.risk_score
            for file_result in result.file_results
        ]

        scores.extend(
            threat.score
            for threat in result.archive_threats
        )

        result.risk_score = min(max(scores, default=0), 100)

        result.risk_level = self.file_analyzer._calculate_risk_level(
            result.risk_score
        )