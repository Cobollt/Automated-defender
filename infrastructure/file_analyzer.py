from pathlib import Path
from typing import List

from domain.enums import RiskLevel, ThreatType
from domain.models import DetectedThreat, FileScanResult
from utils.entropy import calculate_entropy
from utils.hashing import calculate_sha256


class FileAnalyzer:
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".jar", ".msi", ".dmg", ".pkg", ".sh", ".command", ".app"
    }

    MAGIC_SIGNATURES = {
        b"MZ": "Windows executable PE",
        b"\x7fELF": "Linux executable ELF",
        b"\xcf\xfa\xed\xfe": "macOS Mach-O",
        b"\xfe\xed\xfa\xcf": "macOS Mach-O",
        b"\xca\xfe\xba\xbe": "macOS Universal Binary",
        b"PK\x03\x04": "ZIP archive",
        b"%PDF": "PDF document",
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
        b"CreateRemoteThread",
        b"VirtualAlloc",
        b"WriteProcessMemory",
        b"chmod +x",
    ]

    ENTROPY_LIMIT = 7.2
    MAX_READ_SIZE = 1024 * 1024

    def analyze(self, file_path: Path) -> FileScanResult:
        threats: List[DetectedThreat] = []
        risk_score = 0

        sha256 = calculate_sha256(file_path)

        data = self._read_sample(file_path)
        lowered_data = data.lower()

        extension_threats = self._check_extension(file_path)
        threats.extend(extension_threats)

        magic_threats = self._check_magic_signature(file_path, data)
        threats.extend(magic_threats)

        string_threats = self._check_suspicious_strings(file_path, lowered_data)
        threats.extend(string_threats)

        entropy_threats = self._check_entropy(file_path, data)
        threats.extend(entropy_threats)

        for threat in threats:
            risk_score += threat.score

        risk_score = min(risk_score, 100)
        risk_level = self._calculate_risk_level(risk_score)

        return FileScanResult(
            file_path=file_path,
            sha256=sha256,
            risk_score=risk_score,
            risk_level=risk_level,
            threats=threats
        )

    def _read_sample(self, file_path: Path) -> bytes:
        with file_path.open("rb") as file:
            return file.read(self.MAX_READ_SIZE)

    def _check_extension(self, file_path: Path) -> List[DetectedThreat]:
        threats: List[DetectedThreat] = []
        extension = file_path.suffix.lower()

        if extension in self.SUSPICIOUS_EXTENSIONS:
            threats.append(
                DetectedThreat(
                    threat_type=ThreatType.SUSPICIOUS_EXTENSION,
                    description="Suspicious file extension: {}".format(extension),
                    score=20,
                    file_path=file_path
                )
            )

        return threats

    def _check_magic_signature(self, file_path: Path, data: bytes) -> List[DetectedThreat]:
        threats: List[DetectedThreat] = []

        for signature, description in self.MAGIC_SIGNATURES.items():
            if data.startswith(signature):
                if description in {
                    "Windows executable PE",
                    "Linux executable ELF",
                    "macOS Mach-O",
                    "macOS Universal Binary",
                }:
                    score = 30
                    threat_type = ThreatType.EXECUTABLE_SIGNATURE
                else:
                    score = 5
                    threat_type = ThreatType.UNKNOWN_FORMAT

                threats.append(
                    DetectedThreat(
                        threat_type=threat_type,
                        description="Detected file signature: {}".format(description),
                        score=score,
                        file_path=file_path
                    )
                )

        return threats

    def _check_suspicious_strings(self, file_path: Path, data: bytes) -> List[DetectedThreat]:
        threats: List[DetectedThreat] = []

        for marker in self.SUSPICIOUS_STRINGS:
            if marker.lower() in data:
                threats.append(
                    DetectedThreat(
                        threat_type=ThreatType.SUSPICIOUS_STRING,
                        description="Suspicious string found: {}".format(
                            marker.decode(errors="ignore")
                        ),
                        score=15,
                        file_path=file_path
                    )
                )

        return threats

    def _check_entropy(self, file_path: Path, data: bytes) -> List[DetectedThreat]:
        threats: List[DetectedThreat] = []

        entropy = calculate_entropy(data)

        if entropy > self.ENTROPY_LIMIT:
            threats.append(
                DetectedThreat(
                    threat_type=ThreatType.HIGH_ENTROPY,
                    description="High entropy detected: {:.2f}".format(entropy),
                    score=20,
                    file_path=file_path
                )
            )

        return threats

    def _calculate_risk_level(self, risk_score: int) -> RiskLevel:
        if risk_score >= 80:
            return RiskLevel.CRITICAL

        if risk_score >= 60:
            return RiskLevel.HIGH

        if risk_score >= 35:
            return RiskLevel.MEDIUM

        if risk_score > 0:
            return RiskLevel.LOW

        return RiskLevel.SAFE