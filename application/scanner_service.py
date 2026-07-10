from pathlib import Path

from domain.enums import ScanStatus
from domain.models import ScanResult
from infrastructure.archive_detector import ArchiveDetector
from infrastructure.file_analyzer import FileAnalyzer
from infrastructure.safe_extractor import SafeExtractor
from infrastructure.temp_manager import TempManager


class ScannerService:
    def __init__(self) -> None:
        self.archive_detector = ArchiveDetector()
        self.file_analyzer = FileAnalyzer()
        self.safe_extractor = SafeExtractor()
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

    def _scan_archive(self, archive_path: Path, result: ScanResult) -> None:
        archive_threats = self.safe_extractor.inspect_archive(archive_path)

        temp_dir = self.temp_manager.create_temp_dir()

        try:
            extracted_files = self.safe_extractor.extract(archive_path, temp_dir)

            for extracted_file in extracted_files:
                file_result = self.file_analyzer.analyze(extracted_file)

                for threat in archive_threats:
                    file_result.threats.append(threat)
                    file_result.risk_score += threat.score

                file_result.risk_score = min(file_result.risk_score, 100)
                file_result.risk_level = self.file_analyzer._calculate_risk_level(
                    file_result.risk_score
                )

                result.file_results.append(file_result)
                result.total_files_checked += 1

        finally:
            self.temp_manager.cleanup(temp_dir)

    def _finalize_result(self, result: ScanResult) -> None:
        if not result.file_results:
            result.total_threats_found = 0
            result.risk_score = 0
            result.risk_level = self.file_analyzer._calculate_risk_level(0)
            return

        result.total_threats_found = sum(
            len(file_result.threats)
            for file_result in result.file_results
        )

        result.risk_score = max(
            file_result.risk_score
            for file_result in result.file_results
        )

        result.risk_level = self.file_analyzer._calculate_risk_level(
            result.risk_score
        )