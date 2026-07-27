from pathlib import Path

from application.risk_evaluator import RiskEvaluator
from domain.enums import RiskLevel, ThreatType
from domain.models import DetectedThreat, FileScanResult


def test_zero_score_is_safe() -> None:
    evaluator = RiskEvaluator()

    assert (
        evaluator.calculate_level(0)
        == RiskLevel.SAFE
    )


def test_low_risk_level() -> None:
    evaluator = RiskEvaluator()

    assert (
        evaluator.calculate_level(1)
        == RiskLevel.LOW
    )

    assert (
        evaluator.calculate_level(34)
        == RiskLevel.LOW
    )


def test_medium_risk_level() -> None:
    evaluator = RiskEvaluator()

    assert (
        evaluator.calculate_level(35)
        == RiskLevel.MEDIUM
    )

    assert (
        evaluator.calculate_level(59)
        == RiskLevel.MEDIUM
    )


def test_high_risk_level() -> None:
    evaluator = RiskEvaluator()

    assert (
        evaluator.calculate_level(60)
        == RiskLevel.HIGH
    )

    assert (
        evaluator.calculate_level(79)
        == RiskLevel.HIGH
    )


def test_critical_risk_level() -> None:
    evaluator = RiskEvaluator()

    assert (
        evaluator.calculate_level(80)
        == RiskLevel.CRITICAL
    )

    assert (
        evaluator.calculate_level(100)
        == RiskLevel.CRITICAL
    )

    assert (
        evaluator.calculate_level(150)
        == RiskLevel.CRITICAL
    )


def test_negative_score_is_normalized_to_zero() -> None:
    evaluator = RiskEvaluator()

    assert (
        evaluator.normalize_score(-20)
        == 0
    )

    assert (
        evaluator.calculate_level(-20)
        == RiskLevel.SAFE
    )


def test_score_is_limited_to_100() -> None:
    evaluator = RiskEvaluator()

    assert (
        evaluator.normalize_score(150)
        == 100
    )


def test_file_score_is_sum_of_different_threat_types() -> None:
    evaluator = RiskEvaluator()

    threats = [
        DetectedThreat(
            threat_type=(
                ThreatType
                .SUSPICIOUS_EXTENSION
            ),
            description=(
                "Suspicious extension"
            ),
            score=20,
        ),
        DetectedThreat(
            threat_type=(
                ThreatType
                .SUSPICIOUS_STRING
            ),
            description=(
                "Suspicious string"
            ),
            score=15,
        ),
    ]

    assert (
        evaluator
        .calculate_file_score(
            threats
        )
        == 35
    )


def test_negative_threat_score_is_ignored() -> None:
    evaluator = RiskEvaluator()

    threats = [
        DetectedThreat(
            threat_type=(
                ThreatType
                .SUSPICIOUS_EXTENSION
            ),
            description=(
                "Positive threat"
            ),
            score=20,
        ),
        DetectedThreat(
            threat_type=(
                ThreatType
                .UNKNOWN_FORMAT
            ),
            description=(
                "Invalid negative score"
            ),
            score=-100,
        ),
    ]

    assert (
        evaluator
        .calculate_file_score(
            threats
        )
        == 20
    )


def test_repeated_suspicious_strings_are_capped() -> None:
    evaluator = RiskEvaluator()

    threats = [
        DetectedThreat(
            threat_type=(
                ThreatType
                .SUSPICIOUS_STRING
            ),
            description=(
                f"Threat {index}"
            ),
            score=15,
        )
        for index in range(10)
    ]

    assert (
        evaluator
        .calculate_file_score(
            threats
        )
        == 30
    )


def test_file_score_is_limited_to_100() -> None:
    evaluator = RiskEvaluator()

    threats = [
        DetectedThreat(
            threat_type=(
                ThreatType
                .SUSPICIOUS_EXTENSION
            ),
            description="Extension",
            score=20,
        ),
        DetectedThreat(
            threat_type=(
                ThreatType
                .EXECUTABLE_SIGNATURE
            ),
            description="Executable",
            score=30,
        ),
        DetectedThreat(
            threat_type=(
                ThreatType
                .SUSPICIOUS_STRING
            ),
            description="String",
            score=30,
        ),
        DetectedThreat(
            threat_type=(
                ThreatType
                .HIGH_ENTROPY
            ),
            description="Entropy",
            score=20,
        ),
    ]

    assert (
        evaluator
        .calculate_file_score(
            threats
        )
        == 100
    )


def test_evaluate_file_result_updates_score_and_level(
    tmp_path: Path,
) -> None:
    evaluator = RiskEvaluator()

    file_result = FileScanResult(
        file_path=(
            tmp_path
            / "danger.exe"
        ),
        sha256="test-hash",
        relative_path=(
            "danger.exe"
        ),
        threats=[
            DetectedThreat(
                threat_type=(
                    ThreatType
                    .SUSPICIOUS_EXTENSION
                ),
                description=(
                    "Suspicious extension"
                ),
                score=20,
            ),
            DetectedThreat(
                threat_type=(
                    ThreatType
                    .EXECUTABLE_SIGNATURE
                ),
                description=(
                    "Executable signature"
                ),
                score=30,
            ),
        ],
    )

    evaluated_result = (
        evaluator
        .evaluate_file_result(
            file_result
        )
    )

    assert (
        evaluated_result
        is file_result
    )

    assert (
        evaluated_result
        .risk_score
        == 50
    )

    assert (
        evaluated_result
        .risk_level
        == RiskLevel.MEDIUM
    )


def test_scan_score_uses_highest_file_risk() -> None:
    evaluator = RiskEvaluator()

    first_result = FileScanResult(
        file_path=(
            Path("first.txt")
        ),
        sha256="first-hash",
        risk_score=20,
        risk_level=(
            RiskLevel.LOW
        ),
    )

    second_result = FileScanResult(
        file_path=(
            Path("second.txt")
        ),
        sha256="second-hash",
        risk_score=70,
        risk_level=(
            RiskLevel.HIGH
        ),
    )

    score = (
        evaluator
        .calculate_scan_score(
            file_results=[
                first_result,
                second_result,
            ],
            archive_threats=[],
        )
    )

    assert score == 70


def test_scan_score_includes_archive_threats() -> None:
    evaluator = RiskEvaluator()

    file_result = FileScanResult(
        file_path=(
            Path("safe.txt")
        ),
        sha256="safe-hash",
        risk_score=0,
        risk_level=(
            RiskLevel.SAFE
        ),
    )

    archive_threat = (
        DetectedThreat(
            threat_type=(
                ThreatType
                .UNSAFE_PATH
            ),
            description=(
                "Unsafe archive path"
            ),
            score=50,
        )
    )

    score = (
        evaluator
        .calculate_scan_score(
            file_results=[
                file_result
            ],
            archive_threats=[
                archive_threat
            ],
        )
    )

    assert score == 50


def test_repeated_archive_threat_type_is_capped() -> None:
    evaluator = RiskEvaluator()

    archive_threats = [
        DetectedThreat(
            threat_type=(
                ThreatType
                .UNSAFE_PATH
            ),
            description=(
                f"Unsafe path {index}"
            ),
            score=50,
        )
        for index in range(10)
    ]

    score = (
        evaluator
        .calculate_scan_score(
            file_results=[],
            archive_threats=(
                archive_threats
            ),
        )
    )

    assert score == 60


def test_empty_scan_has_zero_risk() -> None:
    evaluator = RiskEvaluator()

    score = (
        evaluator
        .calculate_scan_score(
            file_results=[],
            archive_threats=[],
        )
    )

    assert score == 0

    assert (
        evaluator
        .calculate_level(
            score
        )
        == RiskLevel.SAFE
    )