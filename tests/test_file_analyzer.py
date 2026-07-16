from pathlib import Path

from application.risk_evaluator import RiskEvaluator
from domain.enums import RiskLevel, ThreatType
from infrastructure.file_analyzer import FileAnalyzer


def create_analyzer() -> FileAnalyzer:
    return FileAnalyzer(
        risk_evaluator=RiskEvaluator()
    )


def test_safe_text_file_has_no_risk(
    safe_text_file: Path,
) -> None:
    analyzer = create_analyzer()

    result = analyzer.analyze(
        safe_text_file,
        relative_path="safe.txt",
    )

    assert result.file_path == safe_text_file
    assert result.relative_path == "safe.txt"
    assert result.sha256
    assert result.risk_score == 0
    assert result.risk_level == RiskLevel.SAFE
    assert result.threats == []


def test_suspicious_script_is_detected(
    suspicious_script: Path,
) -> None:
    analyzer = create_analyzer()

    result = analyzer.analyze(
        suspicious_script,
        relative_path="danger.ps1",
    )

    threat_types = {
        threat.threat_type
        for threat in result.threats
    }

    assert result.relative_path == "danger.ps1"
    assert result.risk_score > 0
    assert result.risk_level != RiskLevel.SAFE

    assert (
        ThreatType.SUSPICIOUS_EXTENSION
        in threat_types
    )

    assert (
        ThreatType.SUSPICIOUS_STRING
        in threat_types
    )

    assert all(
        threat.relative_path == "danger.ps1"
        for threat in result.threats
    )


def test_windows_executable_signature_is_detected(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "renamed.txt"
    file_path.write_bytes(
        b"MZ" + b"\x00" * 100
    )

    result = create_analyzer().analyze(
        file_path,
        relative_path="renamed.txt",
    )

    assert any(
        threat.threat_type
        == ThreatType.EXECUTABLE_SIGNATURE
        for threat in result.threats
    )

    assert result.risk_score >= 30


def test_macos_executable_signature_is_detected(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "binary.dat"
    file_path.write_bytes(
        b"\xcf\xfa\xed\xfe"
        + b"\x00" * 100
    )

    result = create_analyzer().analyze(
        file_path,
        relative_path="binary.dat",
    )

    assert any(
        threat.threat_type
        == ThreatType.EXECUTABLE_SIGNATURE
        for threat in result.threats
    )


def test_archive_signature_is_detected(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "renamed.bin"
    file_path.write_bytes(
        b"PK\x03\x04"
        + b"\x00" * 100
    )

    result = create_analyzer().analyze(
        file_path,
        relative_path="renamed.bin",
    )

    assert any(
        threat.description.startswith(
            "Detected file signature:"
        )
        for threat in result.threats
    )

    assert result.risk_score == 5
    assert result.risk_level == RiskLevel.LOW


def test_suspicious_strings_are_case_insensitive(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "script.txt"

    file_path.write_bytes(
        b"PoWeRsHeLl "
        b"CrEaTeReMoTeThReAd "
        b"ViRtUaLaLlOc"
    )

    result = create_analyzer().analyze(
        file_path,
        relative_path="script.txt",
    )

    descriptions = {
        threat.description.lower()
        for threat in result.threats
    }

    assert any(
        "powershell" in description
        for description in descriptions
    )

    assert any(
        "createremotethread" in description
        for description in descriptions
    )

    assert any(
        "virtualalloc" in description
        for description in descriptions
    )


def test_risk_score_does_not_exceed_100(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.ps1"

    file_path.write_bytes(
        b"MZ "
        b"powershell "
        b"cmd.exe "
        b"createremotethread "
        b"virtualalloc "
        b"writeprocessmemory "
        b"base64 "
        b"eval("
    )

    result = create_analyzer().analyze(
        file_path,
        relative_path="danger.ps1",
    )

    assert result.risk_score == 100
    assert result.risk_level == RiskLevel.CRITICAL


def test_relative_path_is_written_to_each_threat(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.cmd"

    file_path.write_text(
        "cmd.exe powershell",
        encoding="utf-8",
    )

    result = create_analyzer().analyze(
        file_path,
        relative_path="folder/danger.cmd",
    )

    assert result.relative_path == "folder/danger.cmd"

    assert result.threats

    assert all(
        threat.relative_path
        == "folder/danger.cmd"
        for threat in result.threats
    )