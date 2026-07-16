from collections.abc import Iterable

from domain.enums import RiskLevel
from domain.models import DetectedThreat, FileScanResult


class RiskEvaluator:
    MAX_RISK_SCORE = 100

    def calculate_level(self, risk_score: int) -> RiskLevel:
        normalized_score = self.normalize_score(risk_score)

        if normalized_score >= 80:
            return RiskLevel.CRITICAL

        if normalized_score >= 60:
            return RiskLevel.HIGH

        if normalized_score >= 35:
            return RiskLevel.MEDIUM

        if normalized_score > 0:
            return RiskLevel.LOW

        return RiskLevel.SAFE

    def calculate_file_score(
        self,
        threats: Iterable[DetectedThreat],
    ) -> int:
        total_score = sum(
            max(0, threat.score)
            for threat in threats
        )

        return self.normalize_score(total_score)

    def evaluate_file_result(
        self,
        file_result: FileScanResult,
    ) -> FileScanResult:
        file_result.risk_score = self.calculate_file_score(
            file_result.threats
        )

        file_result.risk_level = self.calculate_level(
            file_result.risk_score
        )

        return file_result

    def calculate_scan_score(
        self,
        file_results: Iterable[FileScanResult],
        archive_threats: Iterable[DetectedThreat],
    ) -> int:
        scores = [
            file_result.risk_score
            for file_result in file_results
        ]

        scores.extend(
            max(0, threat.score)
            for threat in archive_threats
        )

        return self.normalize_score(
            max(scores, default=0)
        )

    def normalize_score(self, risk_score: int) -> int:
        return max(
            0,
            min(risk_score, self.MAX_RISK_SCORE),
        )