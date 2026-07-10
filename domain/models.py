from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from domain.enums import RiskLevel, ScanStatus, ThreatType


@dataclass
class DetectedThreat:
    threat_type: ThreatType
    description: str
    score: int
    file_path: Path | None = None


@dataclass
class FileScanResult:
    file_path: Path
    sha256: str
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    threats: list[DetectedThreat] = field(default_factory=list)


@dataclass
class ScanResult:
    target_path: Path
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    total_files_checked: int = 0
    total_threats_found: int = 0
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    file_results: list[FileScanResult] = field(default_factory=list)
    error_message: str | None = None

    def complete(self) -> None:
        self.status = ScanStatus.COMPLETED
        self.finished_at = datetime.now()

    def fail(self, message: str) -> None:
        self.status = ScanStatus.FAILED
        self.error_message = message
        self.finished_at = datetime.now()


@dataclass
class QuarantineResult:
    success: bool
    provider_name: str
    original_path: Path
    quarantine_path: Path | None = None
    message: str | None = None