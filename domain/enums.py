from enum import Enum


class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class FileAction(Enum):
    KEEP = "keep"
    DELETE = "delete"
    QUARANTINE = "quarantine"


class ThreatType(Enum):
    SUSPICIOUS_EXTENSION = "suspicious_extension"
    EXECUTABLE_SIGNATURE = "executable_signature"
    SUSPICIOUS_STRING = "suspicious_string"
    HIGH_ENTROPY = "high_entropy"
    ARCHIVE_BOMB_RISK = "archive_bomb_risk"
    UNSAFE_PATH = "unsafe_path"
    NESTED_ARCHIVE = "nested_archive"
    UNKNOWN_FORMAT = "unknown_format"