from pathlib import Path

from domain.enums import RiskLevel, ThreatType
from infrastructure.file_analyzer import FileAnalyzer


def test_safe_text_file_has_no_risk(
    safe_text_file: Path,
) -> None:
    analyzer = FileAnalyzer()

    result = analyzer.analyze(safe_text_file)

    assert result.file_path == safe_text_file
    assert result.sha256
    assert result.risk_score == 0
    assert result.risk_level == RiskLevel.SAFE
    assert result.threats == []


def test_suspicious_script_is_detected(
    suspicious_script: Path,
) -> None:
    analyzer = FileAnalyzer()

    result = analyzer.analyze(suspicious_script)

    threat_types = {
        threat.threat_type
        for threat in result.threats
    }

    assert result.risk_score > 0
    assert result.risk_level != RiskLevel.SAFE
    assert ThreatType.SUSPICIOUS_EXTENSION in threat_types
    assert ThreatType.SUSPICIOUS_STRING in threat_types


def test_windows_executable_signature_is_detected(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "renamed.txt"
    file_path.write_bytes(b"MZ" + b"\x00" * 100)

    analyzer = FileAnalyzer()
    result = analyzer.analyze(file_path)

    assert any(
        threat.threat_type
        == ThreatType.EXECUTABLE_SIGNATURE
        for threat in result.threats
    )


def test_risk_score_does_not_exceed_100(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "danger.ps1"

    file_path.write_bytes(
        b"MZ "
        b"powershell "
        b"cmd.exe "
        b"CreateRemoteThread "
        b"VirtualAlloc "
        b"WriteProcessMemory "
        b"base64 "
        b"eval("
    )

    result = FileAnalyzer().analyze(file_path)

    assert result.risk_score <= 100