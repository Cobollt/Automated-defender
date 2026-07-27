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

    SUSPICIOUS_STRINGS = (
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
    )

    ENTROPY_LIMIT = 7.2
    MIN_ENTROPY_SAMPLE_SIZE = 1024
    SAMPLE_CHUNK_SIZE = 1024 * 1024

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
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(
                f"File does not exist: {file_path}"
            )

        if not file_path.is_file():
            raise ValueError(
                "File analyzer accepts only regular files: "
                f"{file_path}"
            )

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
        file_size = file_path.stat().st_size

        with file_path.open("rb") as file:
            head = file.read(
                self.SAMPLE_CHUNK_SIZE
            )

            if file_size <= self.SAMPLE_CHUNK_SIZE:
                return head

            tail_size = min(
                self.SAMPLE_CHUNK_SIZE,
                file_size - len(head),
            )

            if tail_size <= 0:
                return head

            file.seek(
                -tail_size,
                2,
            )

            tail = file.read(
                tail_size
            )

        return head + tail

    def _check_extension(
        self,
        file_path: Path,
        relative_path: str | None,
    ) -> list[DetectedThreat]:
        extension = self._effective_suffix(
            file_path=file_path,
            relative_path=relative_path,
        )

        if (
            extension
            not in self.SUSPICIOUS_EXTENSIONS
        ):
            return []

        return [
            DetectedThreat(
                threat_type=(
                    ThreatType
                    .SUSPICIOUS_EXTENSION
                ),
                description=(
                    "Suspicious file extension: "
                    f"{extension}"
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
        detected_type = (
            FileTypeDetector.detect(
                data
            )
        )

        if detected_type is None:
            return []

        if detected_type.is_executable:
            return [
                DetectedThreat(
                    threat_type=(
                        ThreatType
                        .EXECUTABLE_SIGNATURE
                    ),
                    description=(
                        "Detected executable "
                        "signature: "
                        f"{detected_type.name}"
                    ),
                    score=30,
                    file_path=file_path,
                    relative_path=relative_path,
                )
            ]

        if detected_type.is_archive:
            return [
                DetectedThreat(
                    threat_type=(
                        ThreatType
                        .UNSUPPORTED_ARCHIVE
                    ),
                    description=(
                        "Archive signature "
                        "reached file analysis "
                        "without a matching "
                        "archive reader: "
                        f"{detected_type.name}"
                    ),
                    score=10,
                    file_path=file_path,
                    relative_path=relative_path,
                )
            ]

        return []

    def _check_suspicious_strings(
        self,
        file_path: Path,
        data: bytes,
        relative_path: str | None,
    ) -> list[DetectedThreat]:
        threats: list[
            DetectedThreat
        ] = []

        lowered_data = (
            data.lower()
        )

        for marker in (
            self.SUSPICIOUS_STRINGS
        ):
            if (
                marker
                not in lowered_data
            ):
                continue

            threats.append(
                DetectedThreat(
                    threat_type=(
                        ThreatType
                        .SUSPICIOUS_STRING
                    ),
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
        if (
            len(data)
            < self.MIN_ENTROPY_SAMPLE_SIZE
        ):
            return []

        entropy = (
            calculate_entropy(
                data
            )
        )

        if (
            entropy
            <= self.ENTROPY_LIMIT
        ):
            return []

        return [
            DetectedThreat(
                threat_type=(
                    ThreatType
                    .HIGH_ENTROPY
                ),
                description=(
                    "High entropy detected: "
                    f"{entropy:.2f}"
                ),
                score=20,
                file_path=file_path,
                relative_path=relative_path,
            )
        ]

    @staticmethod
    def _effective_suffix(
        file_path: Path,
        relative_path: str | None,
    ) -> str:
        if relative_path:
            member_name = (
                relative_path
                .rsplit(
                    "!/",
                    1,
                )[-1]
            )

            suffix = (
                Path(member_name)
                .suffix
                .lower()
            )

            if suffix:
                return suffix

        return (
            file_path
            .suffix
            .lower()
        )