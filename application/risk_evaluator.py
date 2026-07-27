from collections import defaultdict
from collections.abc import Iterable

from domain.enums import RiskLevel, ThreatType
from domain.models import DetectedThreat, FileScanResult


class RiskEvaluator:
    MAX_RISK_SCORE = 100

    SAFE_MAX = 0
    LOW_MAX = 34
    MEDIUM_MAX = 59
    HIGH_MAX = 79

    THREAT_TYPE_CAPS = {
        ThreatType.SUSPICIOUS_EXTENSION: 20,
        ThreatType.EXECUTABLE_SIGNATURE: 30,
        ThreatType.SUSPICIOUS_STRING: 30,
        ThreatType.HIGH_ENTROPY: 20,
        ThreatType.ARCHIVE_BOMB_RISK: 60,
        ThreatType.UNSAFE_PATH: 60,
        ThreatType.NESTED_ARCHIVE: 35,
        ThreatType.ENCRYPTED_ARCHIVE: 25,
        ThreatType.UNSUPPORTED_ARCHIVE: 25,
        ThreatType.UNKNOWN_FORMAT: 20,
    }

    def calculate_level(
        self,
        risk_score: int,
    ) -> RiskLevel:
        normalized_score = self.normalize_score(
            risk_score
        )

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
        grouped_scores: dict[
            ThreatType,
            int,
        ] = defaultdict(int)

        for threat in threats:
            grouped_scores[
                threat.threat_type
            ] += max(
                0,
                threat.score,
            )

        total_score = 0

        for (
            threat_type,
            score,
        ) in grouped_scores.items():
            cap = self.THREAT_TYPE_CAPS.get(
                threat_type,
                self.MAX_RISK_SCORE,
            )

            total_score += min(
                score,
                cap,
            )

        return self.normalize_score(
            total_score
        )

    def evaluate_file_result(
        self,
        file_result: FileScanResult,
    ) -> FileScanResult:
        file_result.risk_score = (
            self.calculate_file_score(
                file_result.threats
            )
        )

        file_result.risk_level = (
            self.calculate_level(
                file_result.risk_score
            )
        )

        return file_result

    def calculate_scan_score(
        self,
        file_results: Iterable[FileScanResult],
        archive_threats: Iterable[DetectedThreat],
    ) -> int:
        file_score = max(
            (
                self.normalize_score(
                    file_result.risk_score
                )
                for file_result
                in file_results
            ),
            default=0,
        )

        archive_score = self.calculate_file_score(
            archive_threats
        )

        return self.normalize_score(
            max(
                file_score,
                archive_score,
            )
        )

    def normalize_score(
        self,
        risk_score: int,
    ) -> int:
        return max(
            0,
            min(
                int(risk_score),
                self.MAX_RISK_SCORE,
            ),
        )