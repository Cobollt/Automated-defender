from pathlib import Path

from application.risk_evaluator import RiskEvaluator
from domain.enums import ThreatType
from domain.models import DetectedThreat, FileScanResult
from utils.entropy import calculate_entropy
from utils.file_type import FileTypeDetector
from utils.hashing import calculate_sha256


class FileAnalyzer:
    SUSPICIOUS_EXTENSIONS = {
        ".exe",
        ".dll",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".msi",
        ".dmg",
        ".pkg",
        ".sh",
        ".command",
        ".app",
    }

    SUSPICIOUS_STRINGS = [
        b"powershell",
        b"cmd.exe",
        b"wscript",
        b"cscript",
        b"osascript",
        b"launchctl",
        b"curl ",
        b"wget ",
        b"base64",
        b"eval(",
        b"createremotethread",
        b"virtualalloc",
        b"writeprocessmemory",
        b"chmod +x",
    ]

    ENTROPY_LIMIT = 7.2
    MAX_READ_SIZE = 1024 * 1024

    def __init__(
        self,
        risk_evaluator: RiskEvaluator,
    ) -> None:
        self._risk_evaluator = risk_evaluator

    def analyze(
        self,
        file_path: Path,
        relative_path: str | None = None,
    ) -> FileScanResult:
        sha256 = calculate_sha256(file_path)
        data = self._read_sample(file_path)

        threats: list[DetectedThreat] = []

        threats.extend(
            self._check_extension(
                file_path=file_path,
                relative_path=relative_path,
            )
        )

        threats.extend(
            self._check_file_signature(
                file_path=file_path,
                data=data,
                relative_path=relative_path,
            )
        )

        threats.extend(
            self._check_suspicious_strings(
                file_path=file_path,
                data=data,
                relative_path=relative_path,
            )
        )

        threats.extend(
            self._check_entropy(
                file_path=file_path,
                data=data,
                relative_path=relative_path,
            )
        )

        file_result = FileScanResult(
            file_path=file_path,
            sha256=sha256,
            relative_path=relative_path,
            threats=threats,
        )

        return self._risk_evaluator.evaluate_file_result(
            file_result
        )

    def _read_sample(
        self,
        file_path: Path,
    ) -> bytes:
        with file_path.open("rb") as file:
            return file.read(self.MAX_READ_SIZE)

    def _check_extension(
        self,
        file_path: Path,
        relative_path: str | None,
    ) -> list[DetectedThreat]:
        extension = file_path.suffix.lower()

        if extension not in self.SUSPICIOUS_EXTENSIONS:
            return []

        return [
            DetectedThreat(
                threat_type=ThreatType.SUSPICIOUS_EXTENSION,
                description=(
                    f"Suspicious file extension: {extension}"
                ),
                score=20,
                file_path=file_path,
                relative_path=relative_path,
            )
        ]

    def _check_file_signature(
        self,
        file_path: Path,
        data: bytes,
        relative_path: str | None,
    ) -> list[DetectedThreat]:
        detected_type = FileTypeDetector.detect(data)

        if detected_type is None:
            return []

        if detected_type.is_executable:
            threat_type = ThreatType.EXECUTABLE_SIGNATURE
            score = 30

        elif detected_type.is_archive:
            threat_type = ThreatType.UNKNOWN_FORMAT
            score = 5

        elif detected_type.is_document:
            threat_type = ThreatType.UNKNOWN_FORMAT
            score = 5

        else:
            return []

        return [
            DetectedThreat(
                threat_type=threat_type,
                description=(
                    "Detected file signature: "
                    f"{detected_type.name}"
                ),
                score=score,
                file_path=file_path,
                relative_path=relative_path,
            )
        ]

    def _check_suspicious_strings(
        self,
        file_path: Path,
        data: bytes,
        relative_path: str | None,
    ) -> list[DetectedThreat]:
        threats: list[DetectedThreat] = []
        lowered_data = data.lower()

        for marker in self.SUSPICIOUS_STRINGS:
            if marker not in lowered_data:
                continue

            threats.append(
                DetectedThreat(
                    threat_type=ThreatType.SUSPICIOUS_STRING,
                    description=(
                        "Suspicious string found: "
                        f"{marker.decode(errors='ignore')}"
                    ),
                    score=15,
                    file_path=file_path,
                    relative_path=relative_path,
                )
            )

        return threats

    def _check_entropy(
        self,
        file_path: Path,
        data: bytes,
        relative_path: str | None,
    ) -> list[DetectedThreat]:
        entropy = calculate_entropy(data)

        if entropy <= self.ENTROPY_LIMIT:
            return []

        return [
            DetectedThreat(
                threat_type=ThreatType.HIGH_ENTROPY,
                description=(
                    f"High entropy detected: {entropy:.2f}"
                ),
                score=20,
                file_path=file_path,
                relative_path=relative_path,
            )
        ]